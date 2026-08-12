// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
	BINARY_DATA, CLOSE, EXTENDED_LEN_2, EXTENDED_LEN_8, FIN, MASKED, PING, PONG, close_frame,
	dns_to_ws, ws_to_dns,
};

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
	let mut messages = [
		[FIN | BINARY_DATA, MASKED | 3, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2, 3],
		[FIN | BINARY_DATA, MASKED | 3, 0xf0, 0xf0, 0xf0, 0xf0, 4, 5, 6],
	];
	let buf = messages.as_flattened_mut();
	let mut dns_data = [0; 32];
	let (translated_size, fragment_end, pong, end) = ws_to_dns(buf, &mut dns_data, 0).unwrap();
	assert_eq!(pong, 0);
	assert_eq!(fragment_end, translated_size);
	assert_eq!(end, buf.len());
	assert_eq!(dns_data[..translated_size], [0, 3, 0xf1, 0xf2, 0xf3, 0, 3, 0xf4, 0xf5, 0xf6]);
}

#[test]
fn ws_to_dns_invalid_opcode() {
	// Opcode 0x1 is a text message (not allowed by DoWS).
	let mut buf = [FIN | 0x1, MASKED];
	assert_eq!(ws_to_dns(&mut buf, &mut [], 0), Err(1003));
}

#[test]
fn ws_to_dns_unmasked() {
	// Client frames must be masked.
	let mut buf = [FIN | BINARY_DATA, 0x04];
	assert_eq!(ws_to_dns(&mut buf, &mut [], 0), Err(1002));
}

#[test]
fn ws_to_dns_extended_length() {
	// A 126-byte fragment uses the 2-byte extended length encoding.
	let mut buf = vec![FIN | BINARY_DATA, MASKED | EXTENDED_LEN_2, 0, 126, 0, 0, 0, 0];
	buf.extend(std::iter::repeat_n(9u8, 126));
	let mut dns_data = [0; 128];
	let (translated_size, fragment_end, pong, end) = ws_to_dns(&mut buf, &mut dns_data, 0).unwrap();
	assert_eq!(pong, 0);
	assert_eq!(translated_size, 128);
	assert_eq!(fragment_end, translated_size);
	assert_eq!(end, buf.len());
	assert_eq!(dns_data[..2], [0, 126]);
	assert!(dns_data[2..128].iter().all(|&b| b == 9));
}

#[test]
fn ws_to_dns_truncated_extended_length() {
	// The extended length prefix is incomplete, so processing stops.
	let mut buf = [FIN | BINARY_DATA, MASKED | EXTENDED_LEN_2, 0x00];
	assert_eq!(ws_to_dns(&mut buf, &mut [], 0), Ok((0, 0, 0, 0)));
}

#[test]
fn ws_to_dns_eight_byte_length() {
	// The 8-byte extended length never occurs in DoWS and is rejected.
	let mut buf = [FIN | BINARY_DATA, MASKED | EXTENDED_LEN_8];
	assert_eq!(ws_to_dns(&mut buf, &mut [], 0), Err(1009));
}

#[test]
fn ws_to_dns_truncated_mask() {
	// Only 2 of the 4 mask bytes are present, so processing stops.
	let mut buf = [FIN | BINARY_DATA, MASKED | 2, 0xf0, 0xf0];
	assert_eq!(ws_to_dns(&mut buf, &mut [], 0), Ok((0, 0, 0, 0)));
}

#[test]
fn ws_to_dns_truncated_data() {
	// The frame declares 4 payload bytes but only 2 are present.
	let mut buf = [FIN | BINARY_DATA, MASKED | 4, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2];
	let mut dns_data = [0; 8];
	assert_eq!(ws_to_dns(&mut buf, &mut dns_data, 0), Ok((0, 0, 0, 0)));
}

#[test]
fn ws_to_dns_close() {
	// A CLOSE frame maps to a normal-closure error.
	let mut buf = [FIN | CLOSE, MASKED, 0, 0, 0, 0];
	assert_eq!(ws_to_dns(&mut buf, &mut [], 0), Err(1000));
}

#[test]
fn ws_to_dns_ping() {
	// A PING is answered by a PONG written in place at the front of ws_data.
	let mut buf = [FIN | PING, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2];
	let mut dns_data = [0; 8];
	let (translated_size, fragment_end, pong, end) = ws_to_dns(&mut buf, &mut dns_data, 0).unwrap();
	assert_eq!(translated_size, 0);
	assert_eq!(fragment_end, 0);
	assert_eq!(pong, 4);
	assert_eq!(end, buf.len());
	assert_eq!(buf[..pong], [FIN | PONG, 2, 0xf1, 0xf2]);
}

#[test]
fn ws_to_dns_ping_too_long() {
	// Ping frames must not carry more than 125 bytes.
	let mut buf = vec![FIN | PING, MASKED | EXTENDED_LEN_2, 0, 126, 0, 0, 0, 0];
	buf.extend(std::iter::repeat_n(0, 126));
	assert_eq!(ws_to_dns(&mut buf, &mut [], 0), Err(1002));
}

#[test]
fn ws_to_dns_pong_is_ignored() {
	// Incoming PONG frames are simply skipped.
	let mut buf = [FIN | PONG, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2];
	let mut dns_data = [0; 8];
	let (translated_size, fragment_end, pong, end) = ws_to_dns(&mut buf, &mut dns_data, 0).unwrap();
	assert_eq!(translated_size, 0);
	assert_eq!(fragment_end, 0);
	assert_eq!(pong, 0);
	assert_eq!(end, buf.len());
}

#[test]
fn ws_to_dns_illegal_continuation() {
	// A continuation frame with no message in progress is illegal.
	let mut buf = [FIN, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2];
	let mut dns_data = [0; 8];
	assert_eq!(ws_to_dns(&mut buf, &mut dns_data, 0), Err(1002));
}

#[test]
fn ws_to_dns_fragmented_message() {
	// A binary frame without FIN followed by a continuation frame with FIN
	// form a single DNS message.
	let mut fragments = [
		[BINARY_DATA, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2],
		[FIN, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 3, 4],
	];
	let buf = fragments.as_flattened_mut();
	let mut dns_data = [0; 8];
	let (translated_size, fragment_end, pong, end) = ws_to_dns(buf, &mut dns_data, 0).unwrap();
	assert_eq!(pong, 0);
	assert_eq!(translated_size, 6);
	assert_eq!(fragment_end, translated_size);
	assert_eq!(end, buf.len());
	assert_eq!(dns_data[..translated_size], [0, 4, 0xf1, 0xf2, 0xf3, 0xf4]);
}

#[test]
fn ws_to_dns_output_full() {
	// The first message fits, the second does not, so processing stops and
	// ws_pos is rewound to the start of the unprocessed frame.
	let mut messages = [
		[FIN | BINARY_DATA, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2],
		[FIN | BINARY_DATA, MASKED | 2, 0xf0, 0xf0, 0xf0, 0xf0, 1, 2],
	];
	let buf = messages.as_flattened_mut();
	let mut dns_data = [0; 4];
	let (translated_size, fragment_end, pong, end) = ws_to_dns(buf, &mut dns_data, 0).unwrap();
	assert_eq!(pong, 0);
	assert_eq!(translated_size, 4);
	assert_eq!(fragment_end, 4);
	assert_eq!(end, 8);
	assert_eq!(dns_data[..translated_size], [0, 2, 0xf1, 0xf2]);
}

#[test]
fn ws_to_dns_message_too_long() {
	// Two 65535-byte fragments accumulate into a message that no longer
	// fits in the u16 DNS length prefix.
	let mut buf = vec![BINARY_DATA, MASKED | EXTENDED_LEN_2, 0xFF, 0xFF, 0, 0, 0, 0];
	buf.extend(std::iter::repeat_n(0, 65535));
	buf.extend_from_slice(&[FIN, MASKED | EXTENDED_LEN_2, 0xFF, 0xFF, 0, 0, 0, 0]);
	buf.extend(std::iter::repeat_n(0, 65535));
	// 1 free byte in addition to the partial DNS message from to the first fragment
	let mut dns_data = vec![0; 65535 + 2 + 1];
	assert_eq!(ws_to_dns(&mut buf, &mut dns_data, 0), Err(1009));
}
