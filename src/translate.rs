// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(test)]
mod tests;

use std::{
	fmt::Display,
	io::{Cursor, Write},
	ops::Range,
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

/// Builds a server-to-client WebSocket close frame (RFC 6455,
/// Section 5.5.1) with the given status `code` and `reason` into `buf`,
/// returning the written slice. It is truncated to fit the 125-byte
/// control-frame payload limit.
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

/// Buffers and cursors holding the in- and outputs of [`ws_to_dns`].
pub struct WsToDnsState {
	/// End of pending pong replies at the front of `ws`. The caller consumes
	/// them by sending `ws[..pong]` and resetting `pong`.
	pub pong: usize,
	/// Unprocessed WS input in `ws`; `pong..ws_remainder.start` is processed
	/// input of no further use. The caller reclaims the space of both areas
	/// by moving `ws[ws_remainder]` to the front and resetting `pong` and
	/// `ws_remainder`. New input should be read into `ws[ws_remainder.end..]`.
	pub ws_remainder: Range<usize>,
	/// End of complete DNS TCP messages at the front of `dns`. The caller
	/// consumes them by reading `dns[..dns_out]` and resetting `dns_out`.
	pub dns_out: usize,
	/// End of the incomplete DNS message fragment in `dns_out..dns_pos`.
	pub dns_pos: usize,
	/// WS input; fits a maximum sized frame: 2 header bytes, 2 extended
	/// length bytes, 4 mask bytes, and 65535 data bytes.
	pub ws: [u8; 65535 + 8],
	/// DNS TCP output; fits a maximum sized message with its 2 length bytes.
	pub dns: [u8; 65535 + 2],
}

impl Default for WsToDnsState {
	fn default() -> Self {
		Self { pong: 0, ws_remainder: 0..0, dns_out: 0, dns_pos: 0, ws: [0; _], dns: [0; _] }
	}
}

/// Converts WebSocket framing to DNS TCP framing, translating WS binary data
/// frames from `buf.ws` to DNS messages in `buf.dns` and answering WS ping
/// frames with pong replies built in-place at the front of `buf.ws`.
///
/// Processing stops when the input is exhausted or `dns` is full, or with the
/// WS close code as error on a close frame or protocol violation.
/// Processed input is consumed by advancing `ws_remainder.start`; the frame
/// that stopped processing is not consumed, so an unchanged `WsToDnsState`
/// yields the same result again.
pub fn ws_to_dns(buf: &mut WsToDnsState) -> Result<(), u16> {
	let ws_data = &mut buf.ws[..buf.ws_remainder.end];
	let mut ws_pos = buf.ws_remainder.start;
	let result = loop {
		let Some(minimal_header) =
			ws_data.get(ws_pos..).and_then(|x| x.first_chunk::<2>()).copied()
		else {
			break Ok(());
		};
		match minimal_header[0] {
			// Allow BINARY and continuation frames, with or without FIN.
			// Allow CLOSE, PING, and PONG with FIN only, as fragmented control frames are illegal.
			0x00 | 0x02 | 0x80 | 0x82 | 0x88 | 0x89 | 0x8a => {}
			_ => break Err(1003),
		}
		if minimal_header[1] & MASKED != MASKED {
			break Err(1002);
		}
		let (header_len, fragment_len) = match minimal_header[1] & !MASKED {
			EXTENDED_LEN_2 => match ws_data.get(ws_pos + 2..).and_then(|x| x.first_chunk()) {
				Some(&x) => (4, u16::from_be_bytes(x)),
				_ => break Ok(()),
			},
			EXTENDED_LEN_8 => break Err(1009),
			simple_len => (2, simple_len.into()),
		};
		let Some(mask) =
			ws_data.get(ws_pos + header_len..).and_then(|x| x.first_chunk::<4>()).copied()
		else {
			break Ok(());
		};
		let data_start = ws_pos + header_len + mask.len();
		let data_end = data_start + usize::from(fragment_len);
		if data_end > ws_data.len() {
			break Ok(());
		}
		let data_range = data_start..data_end;
		if minimal_header[0] == MASKED | CLOSE {
			break Err(1000);
		} else if minimal_header[0] == MASKED | PING {
			let Some(fragment_len) =
				u8::try_from(fragment_len).ok().filter(|&c| c < EXTENDED_LEN_2)
			else {
				break Err(1002);
			};
			ws_data[buf.pong] = FIN | PONG;
			ws_data[buf.pong + 1] = fragment_len;
			buf.pong += 2;
			for (i, m) in data_range.zip(mask.iter().cycle()) {
				ws_data[buf.pong] = ws_data[i] ^ m;
				buf.pong += 1;
			}
		} else if minimal_header[0] != MASKED | PONG {
			let start_new_message = minimal_header[0] & TYPE_MASK == BINARY_DATA;
			if start_new_message != (buf.dns_pos == buf.dns_out) {
				break Err(1002);
			}
			let header_size = if start_new_message { 2 } else { 0 };

			let message_len =
				buf.dns_pos + header_size - buf.dns_out - 2 + usize::from(fragment_len);
			let Ok(message_len) = u16::try_from(message_len) else {
				break Err(1009);
			};
			if buf.dns_pos + header_size + data_range.len() > buf.dns.len() {
				break Ok(());
			}
			buf.dns_pos += header_size;
			let data = &ws_data[data_range];
			unmask_into(data, mask, &mut buf.dns[buf.dns_pos..buf.dns_pos + data.len()]);
			buf.dns_pos += data.len();
			if minimal_header[0] & FIN == FIN {
				buf.dns[buf.dns_out..][..2].copy_from_slice(&message_len.to_be_bytes());
				buf.dns_out = buf.dns_pos;
			}
		}
		ws_pos = data_end;
	};
	buf.ws_remainder.start = ws_pos;
	result
}

/// Unmasks WebSocket payload data (RFC 6455, Section 5.3) from `src` into
/// `dst`, which must be at least as long as `src`.
fn unmask_into(src: &[u8], mask: [u8; 4], dst: &mut [u8]) {
	let mask_word = u32::from_ne_bytes(mask);
	let (src_words, src_trailer) = src.as_chunks::<4>();
	let (dst_words, dst_trailer) = dst[..src.len()].as_chunks_mut::<4>();
	for (src_word, dst_word) in src_words.iter().zip(dst_words) {
		// Native-endian words are fine because XOR operates on each byte independently.
		*dst_word = (u32::from_ne_bytes(*src_word) ^ mask_word).to_ne_bytes();
	}
	for ((src_byte, dst_byte), mask_byte) in src_trailer.iter().zip(dst_trailer).zip(mask) {
		*dst_byte = src_byte ^ mask_byte;
	}
}
