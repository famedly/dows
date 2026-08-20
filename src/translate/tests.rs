// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
	BINARY_DATA, CLOSE, EXTENDED_LEN_2, EXTENDED_LEN_8, FIN, MASKED, PING, PONG, WsToDnsState,
	close_frame, dns_to_ws, ws_to_dns,
};

/// Builds a `WsToDnsState` holding the given bytes as unprocessed WS input.
fn buf_with(ws: &[u8]) -> WsToDnsState {
	let mut buf = WsToDnsState::default();
	buf.ws[..ws.len()].copy_from_slice(ws);
	buf.ws_remainder = 0..ws.len();
	buf
}

#[test]
fn close_frame_without_reason() {
	let mut buf = [0; _];
	// 1000 == 0x03e8 (normal closure).
	assert_eq!(close_frame(&mut buf, 1000, ""), [FIN | CLOSE, 2, 0x03, 0xe8]);
}

#[test]
fn close_frame_with_reason() {
	let mut buf = [0; _];
	// 1011 == 0x03f3 (internal error).
	assert_eq!(
		close_frame(&mut buf, 1011, "boom"),
		[FIN | CLOSE, 6, 0x03, 0xf3, b'b', b'o', b'o', b'm']
	);
}

#[test]
fn close_frame_truncates_overlong_reason() {
	let mut buf = [0; _];
	let reason = "x".repeat(200);
	let frame = close_frame(&mut buf, 1000, &reason);
	// The payload is capped at the 125-byte control-frame maximum (2-byte
	// code + 123-byte reason).
	assert_eq!(frame.len(), 2 + 125);
	assert_eq!(frame[1], 125);
	assert_eq!(&frame[4..frame.len() - 3], vec![b'x'; 120].as_slice());
	assert_eq!(&frame[frame.len() - 3..], *b"...");
}

#[test]
fn close_frame_truncates_on_char_boundary() {
	let mut buf = [0; _];
	for i in 0.."🌈".len() {
		// Shift the UTF-8 character to every possible byte position
		let reason = format!("{}{}", " ".repeat(i), "🌈".repeat(42));
		let frame = close_frame(&mut buf, 1000, reason);
		assert!(std::str::from_utf8(&frame[4..]).is_ok());
	}
}

#[test]
fn dns_to_ws_two_short_messages() {
	let mut buf = [255, 255, 255, 255, 0, 4, 1, 2, 3, 4, 0, 3, 1, 2, 3];
	let (translated_size, end) = dns_to_ws(&mut buf, 4);
	assert_eq!(end, buf.len());
	assert_eq!(buf[..translated_size], [0x82, 4, 1, 2, 3, 4, 0x82, 3, 1, 2, 3]);
}

#[test]
fn dns_to_ws_extended_length() {
	// A 126-byte message uses the 2-byte extended length encoding.
	let mut buf = vec![255, 255, 255, 255, 0, 126];
	buf.extend(std::iter::repeat_n(7u8, 126));
	let (translated_size, end) = dns_to_ws(&mut buf, 4);
	assert_eq!(end, buf.len());
	assert_eq!(translated_size, 130);
	assert_eq!(buf[..4], [0x82, 126, 0x00, 126]);
	assert!(buf[4..130].iter().all(|&b| b == 7));
}

#[test]
fn dns_to_ws_incomplete_message() {
	// The declared length (10) exceeds the bytes actually available.
	let mut buf = [0, 0, 0, 0, 0, 10, 1, 2, 3];
	let (translated_size, end) = dns_to_ws(&mut buf, 4);
	assert_eq!(translated_size, 0);
	assert_eq!(end, 4);
}

#[test]
fn ws_to_dns_two_short_messages() {
	let messages = [
		[FIN | BINARY_DATA, MASKED | 3, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2, 3],
		[FIN | BINARY_DATA, MASKED | 3, 0xf0, 0xf0, 0xf0, 0xf0, 4, 5, 6],
	];
	let mut buf = buf_with(messages.as_flattened());
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!(buf.pong, 0);
	assert!(buf.ws_remainder.is_empty());
	assert_eq!(buf.dns_pos, buf.dns_out);
	assert_eq!(buf.dns[..buf.dns_out], [0, 3, 0xf1, 0xf2, 0xf3, 0, 3, 0xf4, 0xf5, 0xf6]);
}

#[test]
fn ws_to_dns_invalid_opcode() {
	// Opcode 0x1 is a text message (not allowed by DoWS).
	assert_eq!(ws_to_dns(&mut buf_with(&[FIN | 0x1, MASKED])), Err(1003));
}

#[test]
fn ws_to_dns_unmasked() {
	// Client frames must be masked.
	assert_eq!(ws_to_dns(&mut buf_with(&[FIN | BINARY_DATA, 0x04])), Err(1002));
}

#[test]
fn ws_to_dns_extended_length() {
	// A 126-byte fragment uses the 2-byte extended length encoding.
	let mut ws = vec![FIN | BINARY_DATA, MASKED | EXTENDED_LEN_2, 0, 126, 0, 0, 0, 0];
	ws.extend(std::iter::repeat_n(9u8, 126));
	let mut buf = buf_with(&ws);
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!(buf.pong, 0);
	assert!(buf.ws_remainder.is_empty());
	assert_eq!((buf.dns_out, buf.dns_pos), (128, 128));
	assert_eq!(buf.dns[..2], [0, 126]);
	assert!(buf.dns[2..128].iter().all(|&b| b == 9));
}

#[test]
fn ws_to_dns_truncated_extended_length() {
	// The extended length prefix is incomplete, so processing stops.
	let mut buf = buf_with(&[FIN | BINARY_DATA, MASKED | EXTENDED_LEN_2, 0x00]);
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!((buf.dns_out, buf.dns_pos, buf.pong), (0, 0, 0));
	assert_eq!(buf.ws_remainder, 0..3);
}

#[test]
fn ws_to_dns_eight_byte_length() {
	// The 8-byte extended length never occurs in DoWS and is rejected.
	assert_eq!(ws_to_dns(&mut buf_with(&[FIN | BINARY_DATA, MASKED | EXTENDED_LEN_8])), Err(1009));
}

#[test]
fn ws_to_dns_truncated_mask() {
	// Only 2 of the 4 mask bytes are present, so processing stops.
	let mut buf = buf_with(&[FIN | BINARY_DATA, MASKED | 2, 0xf0, 0xf0]);
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!((buf.dns_out, buf.dns_pos, buf.pong), (0, 0, 0));
	assert_eq!(buf.ws_remainder, 0..4);
}

#[test]
fn ws_to_dns_truncated_data() {
	// The frame declares 4 payload bytes but only 2 are present.
	let mut buf = buf_with(&[FIN | BINARY_DATA, MASKED | 4, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2]);
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!((buf.dns_out, buf.dns_pos, buf.pong), (0, 0, 0));
	assert_eq!(buf.ws_remainder, 0..8);
}

#[test]
fn ws_to_dns_close() {
	// A CLOSE frame maps to a normal-closure error. It is not consumed, so an
	// unchanged WsToDnsState yields the same result again.
	let mut buf = buf_with(&[FIN | CLOSE, MASKED, 0, 0, 0, 0]);
	assert_eq!(ws_to_dns(&mut buf), Err(1000));
	assert_eq!(ws_to_dns(&mut buf), Err(1000));
}

#[test]
fn ws_to_dns_ping() {
	// A PING is answered by a PONG written in place at the front of ws.
	let mut buf = buf_with(&[FIN | PING, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2]);
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!((buf.dns_out, buf.dns_pos), (0, 0));
	assert_eq!(buf.pong, 4);
	assert!(buf.ws_remainder.is_empty());
	assert_eq!(buf.ws[..buf.pong], [FIN | PONG, 2, 0xf1, 0xf2]);
}

#[test]
fn ws_to_dns_ping_too_long() {
	// Ping frames must not carry more than 125 bytes.
	let mut ws = vec![FIN | PING, MASKED | EXTENDED_LEN_2, 0, 126, 0, 0, 0, 0];
	ws.extend(std::iter::repeat_n(0, 126));
	assert_eq!(ws_to_dns(&mut buf_with(&ws)), Err(1002));
}

#[test]
fn ws_to_dns_pong_before_close() {
	// The pong reply to a PING preceding a CLOSE frame is still produced, and
	// the unconsumed CLOSE frame repeats the result without duplicating pongs.
	let mut ws = vec![FIN | PING, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2];
	ws.extend_from_slice(&[FIN | CLOSE, MASKED, 0, 0, 0, 0]);
	let mut buf = buf_with(&ws);
	assert_eq!(ws_to_dns(&mut buf), Err(1000));
	assert_eq!(buf.ws[..buf.pong], [FIN | PONG, 2, 0xf1, 0xf2]);
	assert_eq!(buf.ws[buf.ws_remainder.clone()], [FIN | CLOSE, MASKED, 0, 0, 0, 0]);
	assert_eq!(ws_to_dns(&mut buf), Err(1000));
	assert_eq!(buf.pong, 4);
}

#[test]
fn ws_to_dns_pong_is_ignored() {
	// Incoming PONG frames are simply skipped.
	let mut buf = buf_with(&[FIN | PONG, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2]);
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!((buf.dns_out, buf.dns_pos, buf.pong), (0, 0, 0));
	assert!(buf.ws_remainder.is_empty());
}

#[test]
fn ws_to_dns_illegal_continuation() {
	// A continuation frame with no message in progress is illegal.
	let mut buf = buf_with(&[FIN, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2]);
	assert_eq!(ws_to_dns(&mut buf), Err(1002));
}

#[test]
fn ws_to_dns_fragmented_message() {
	// A binary frame without FIN followed by a continuation frame with FIN
	// form a single DNS message.
	let fragments = [
		[BINARY_DATA, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2],
		[FIN, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 3, 4],
	];
	let mut buf = buf_with(fragments.as_flattened());
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!(buf.pong, 0);
	assert!(buf.ws_remainder.is_empty());
	assert_eq!((buf.dns_out, buf.dns_pos), (6, 6));
	assert_eq!(buf.dns[..buf.dns_out], [0, 4, 0xf1, 0xf2, 0xf3, 0xf4]);
}

#[test]
fn ws_to_dns_output_full() {
	// A first message fills the dns buffer to 2 bytes short of capacity,
	// so the second message does not fit and its frame is left unconsumed.
	let mut buf = WsToDnsState::default();
	buf.ws[..8].copy_from_slice(&[
		FIN | BINARY_DATA,
		MASKED | EXTENDED_LEN_2,
		0xFF,
		0xFD,
		0,
		0,
		0,
		0,
	]);
	buf.ws_remainder = 0..8 + 65533;
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!(buf.dns_out, 65535);
	assert!(buf.ws_remainder.is_empty());
	buf.ws[..8].copy_from_slice(&[FIN | BINARY_DATA, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2]);
	buf.ws_remainder = 0..8;
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	assert_eq!(buf.dns_out, 65535);
	assert_eq!(buf.ws_remainder, 0..8);
}

#[test]
fn ws_to_dns_message_too_long() {
	// Two 65535-byte fragments accumulate into a message that no longer
	// fits in the u16 DNS length prefix. The erroneous fragment is not
	// consumed, so the result is repeatable.
	let mut buf = WsToDnsState::default();
	buf.ws[..8].copy_from_slice(&[BINARY_DATA, MASKED | EXTENDED_LEN_2, 0xFF, 0xFF, 0, 0, 0, 0]);
	buf.ws_remainder = 0..8 + 65535;
	assert_eq!(ws_to_dns(&mut buf), Ok(()));
	buf.ws[..8].copy_from_slice(&[FIN, MASKED | EXTENDED_LEN_2, 0xFF, 0xFF, 0, 0, 0, 0]);
	buf.ws_remainder = 0..8 + 65535;
	assert_eq!(ws_to_dns(&mut buf), Err(1009));
	assert_eq!(ws_to_dns(&mut buf), Err(1009));
}
