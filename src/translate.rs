// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(test)]
mod tests;

use std::{
	fmt::Display,
	io::{Cursor, Write},
};

const BINARY_DATA: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;
const TYPE_MASK: u8 = 0xF;

/// The last frame of a message.
const FIN: u8 = 0x80;

const MASKED: u8 = 0x80;

/// The actual len is encoded in the next 2 bytes.
const EXTENDED_LEN_2: u8 = 126;

/// The actual len is encoded in the next 8 bytes (never occurs in DoWS).
const EXTENDED_LEN_8: u8 = 127;

/// Builds a server-to-client WebSocket close frame (RFC 6455, 5.5.1) with the
/// given status `code` and `reason` into `buf`, returning the written slice.
/// It is truncated to fit the 125-byte control-frame payload limit.
pub fn close_frame(buf: &mut [u8; 127], code: u16, reason: impl Display) -> &[u8] {
	let mut cursor = Cursor::new(&mut buf[4..]);
	let write_result = write!(cursor, "{reason}");
	let mut reason_len = cursor.position() as usize;
	if write_result.is_err() {
		let trailer = *b"..."; // trailer to indicate truncation
		reason_len -= trailer.len();
		// Truncation may have split a multi-byte character
		if let Err(e) = std::str::from_utf8(&buf[4..4 + reason_len]) {
			reason_len = e.valid_up_to();
		}
		reason_len += trailer.len();
		*buf[4..4 + reason_len].last_chunk_mut().expect("reason_len >= trailer.len") = *b"...";
	}

	buf[0] = FIN | CLOSE;
	buf[1] = (reason_len + 2) as u8;
	buf[2..4].copy_from_slice(&code.to_be_bytes());
	&buf[..4 + reason_len]
}

/// Converts DNS TCP framing (u16) to WebSocket framing in-place.
///
/// The input `buffer` must have a prefix area with unspecified data. The prefix
/// area must contain 2 bytes per DNS message of 126 bytes or larger. The worst
/// case overhead is 2 * floor(length / 128). The real input data starts at
/// `offset`. The first returned index is the end of the translated output. The
/// second returned index is the end of processed input. Unprocessed input
/// should be supplied at `offset` on the next call.
pub fn dns_to_ws(buffer: &mut [u8], offset: usize) -> (usize, usize) {
	let mut input_pos = offset;
	let mut output_pos = 0;
	while let Some(&length_array) = buffer.get(input_pos..).and_then(|x| x.first_chunk()) {
		let len = u16::from_be_bytes(length_array);
		if input_pos + 2 + usize::from(len) > buffer.len() {
			break;
		}
		if len < EXTENDED_LEN_2.into() {
			buffer[output_pos] = FIN | BINARY_DATA;
			buffer[output_pos + 1] = length_array[1];
			output_pos += 2;
		} else {
			buffer[output_pos] = FIN | BINARY_DATA;
			buffer[output_pos + 1] = EXTENDED_LEN_2;
			buffer[output_pos + 2] = length_array[0];
			buffer[output_pos + 3] = length_array[1];
			output_pos += 4;
		}
		input_pos += 2;
		buffer.copy_within(input_pos..input_pos + usize::from(len), output_pos);
		input_pos += usize::from(len);
		output_pos += usize::from(len);
	}
	(output_pos, input_pos)
}

/// Converts WebSocket framing from `ws_data` to DNS TCP framing in `dns_data`,
/// translating WS binary data frames to DNS messages and answering WS ping
/// frames.
///
/// `dns_data` can already contain the start of a message, in case a
/// fragment was processed in the previous call. `dns_data_pos` indicates the
/// end of such a fragment.
///
/// The first returned index is the end of complete DNS TCP data. The second
/// returned index is the end of the current fragment. The third returned index
/// is the end of the pong area. Pong replies are built in-place at the
/// beginning of `ws_data`. The fourth returned index is the end of processed
/// input. Unprocessed input should be supplied at the front on the next call.
///
/// On CLOSE or a protocol error, returns `Err((code, dns_data_complete))` so
/// any DNS messages already completed in this call can still be forwarded.
pub fn ws_to_dns(
	ws_data: &mut [u8],
	dns_data: &mut [u8],
	mut dns_data_pos: usize,
) -> Result<(usize, usize, usize, usize), (u16, usize)> {
	let mut ws_pos = 0;
	let mut dns_data_complete = 0;
	let mut pong_pos = 0;
	while let Some(minimal_header) =
		ws_data.get(ws_pos..).and_then(|x| x.first_chunk::<2>()).copied()
	{
		match minimal_header[0] {
			// Allow BINARY and continuation frames, with or without FIN.
			// Allow CLOSE, PING, and PONG with FIN only, as fragmented control frames are illegal.
			0x00 | 0x02 | 0x80 | 0x82 | 0x88 | 0x89 | 0x8a => {}
			_ => return Err((1003, dns_data_complete)),
		}
		if minimal_header[1] & MASKED != MASKED {
			return Err((1002, dns_data_complete));
		}
		let (header_len, fragment_len) = match minimal_header[1] & !MASKED {
			EXTENDED_LEN_2 => match ws_data.get(ws_pos + 2..).and_then(|x| x.first_chunk()) {
				Some(&x) => (4, u16::from_be_bytes(x)),
				_ => break,
			},
			EXTENDED_LEN_8 => return Err((1009, dns_data_complete)),
			simple_len => (2, simple_len.into()),
		};
		let Some(mask) =
			ws_data.get(ws_pos + header_len..).and_then(|x| x.first_chunk::<4>()).copied()
		else {
			break;
		};
		let data_start = ws_pos + header_len + mask.len();
		let data_range = data_start..data_start + usize::from(fragment_len);
		if data_range.end > ws_data.len() {
			break;
		}
		let old_ws_pos = ws_pos;
		ws_pos = data_range.end;
		if minimal_header[0] == MASKED | CLOSE {
			return Err((1000, dns_data_complete));
		} else if minimal_header[0] == MASKED | PING {
			let Some(fragment_len) =
				u8::try_from(fragment_len).ok().filter(|&c| c < EXTENDED_LEN_2)
			else {
				return Err((1002, dns_data_complete));
			};
			ws_data[pong_pos] = FIN | PONG;
			ws_data[pong_pos + 1] = fragment_len;
			pong_pos += 2;
			for (i, m) in data_range.zip(mask.iter().cycle()) {
				ws_data[pong_pos] = ws_data[i] ^ m;
				pong_pos += 1;
			}
		} else if minimal_header[0] != MASKED | PONG {
			let start_new_message = minimal_header[0] & TYPE_MASK == BINARY_DATA;
			if start_new_message != (dns_data_pos == dns_data_complete) {
				return Err((1002, dns_data_complete));
			}
			let header_size = if start_new_message { 2 } else { 0 };

			let message_len =
				dns_data_pos + header_size - dns_data_complete - 2 + usize::from(fragment_len);
			let Ok(message_len) = u16::try_from(message_len) else {
				return Err((1009, dns_data_complete));
			};
			if dns_data_pos + header_size + data_range.len() > dns_data.len() {
				ws_pos = old_ws_pos;
				break;
			}
			dns_data_pos += header_size;
			for (i, m) in data_range.zip(mask.iter().cycle()) {
				dns_data[dns_data_pos] = ws_data[i] ^ m;
				dns_data_pos += 1;
			}
			if minimal_header[0] & FIN == FIN {
				dns_data[dns_data_complete] = message_len.to_be_bytes()[0];
				dns_data[dns_data_complete + 1] = message_len.to_be_bytes()[1];
				dns_data_complete = dns_data_pos;
			}
		}
	}
	Ok((dns_data_complete, dns_data_pos, pong_pos, ws_pos))
}
