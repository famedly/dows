// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS over WebSocket (DoWS) proxy.

mod translate;
use std::{io, sync::Arc};

use base64ct::{Base64, Encoding};
use httparse::Status;
use percent_encoding::percent_decode_str;
use sha1::{Digest, Sha1};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{
		TcpListener, TcpStream,
		tcp::{ReadHalf, WriteHalf},
	},
	signal::unix::{SignalKind, signal},
	sync::Mutex,
};
use translate::{close_frame, dns_to_ws, ws_to_dns};

const INFO: &str = concat!(
	env!("CARGO_PKG_NAME"),
	" ",
	env!("CARGO_PKG_VERSION"),
	"\r\n",
	"Source code at ",
	env!("CARGO_PKG_REPOSITORY"),
	"/commit/",
	env!("GIT_COMMIT_HASH"),
	"\r\n"
);

/// Policies that are passed to the connection handler
struct Policy {
	/// Allowed origins
	allowed_origins: Option<String>,
	/// Allowed upstreams
	allowed_upstreams: Option<String>,
}

/// The listener accepts any number of connections concurrently, each on
/// its own tokio task.
///
/// SIGTERM (as sent by e.g. `docker stop` or the integration tests) makes
/// the process exit cleanly instead of being killed by the default signal
/// disposition. A clean exit runs the exit hooks, which coverage
/// instrumentation needs to write its profile data. In-flight connections
/// are dropped.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let policy = Arc::new(Policy {
		allowed_upstreams: Some(std::env::var("DOWS_ALLOWED_UPSTREAMS")?).filter(|x| x != "*"),
		allowed_origins: Some(std::env::var("DOWS_ALLOWED_ORIGINS")?).filter(|x| x != "*"),
	});
	let listen_arg = std::env::args().nth(1);
	let listen_str = listen_arg.as_deref().unwrap_or("[::]:8080");
	let listener = TcpListener::bind(listen_str).await?;
	println!("listening on {}", listener.local_addr()?);
	let mut sigterm = signal(SignalKind::terminate())?;
	let mut sigint = signal(SignalKind::interrupt())?;
	loop {
		tokio::select! {
			accepted = listener.accept() => {
				let (sock, _addr) = accepted?;
				tokio::spawn(handle_connection(sock, policy.clone()));
			}
			_ = sigterm.recv()  => return Ok(()),
			_ = sigint.recv() => return Ok(()),
		}
	}
}

/// Handles a single client connection end-to-end: performs the WebSocket
/// handshake, connects to the requested upstream DNS server, then
/// forwards traffic in both directions concurrently until either side
/// closes the connection.
async fn handle_connection(mut sock: TcpStream, policy: Arc<Policy>) -> io::Result<()> {
	let mut buf = [0; 65536];
	let mut data_len = 0;
	let (mut headers, mut request);
	let request_len = loop {
		let size @ 1.. = sock.read(&mut buf[data_len..]).await? else {
			return Err(io::ErrorKind::UnexpectedEof.into());
		};
		data_len += size;
		headers = [httparse::EMPTY_HEADER; 64];
		request = httparse::Request::new(&mut headers);
		match request.parse(&buf[..data_len]) {
			Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
			Ok(Status::Complete(len)) => break len,
			_ => {}
		}
	};

	for h in request.headers.iter() {
		if h.name.eq_ignore_ascii_case("origin") {
			if policy.allowed_origins.as_ref().is_some_and(|x| {
				!x.split(",").map(str::trim).any(|x| x.as_bytes() == h.value.trim_ascii())
			}) {
				let resp = "HTTP/1.1 403 Forbidden\r\n\
                    Connection: close\r\n\
                    Content-Type: text/plain\r\n\r\n";
				sock.write_all(resp.as_bytes()).await?;
				return Ok(());
			}
		}
	}

	if request.path == Some("/") {
		let resp = "HTTP/1.1 200 OK\r\n\
                    Connection: close\r\n\
                    Content-Type: text/plain\r\n\r\n";
		sock.write_all(resp.as_bytes()).await?;
		sock.write_all(INFO.as_bytes()).await?;
		return Ok(());
	}
	let Some(key_header) = websocket_key(&request) else {
		let resp = "HTTP/1.1 426 Upgrade Required\r\n\
                    Upgrade: websocket\r\n\
                    Connection: upgrade, close\r\n\
                    Content-Type: text/plain\r\n\r\n";
		sock.write_all(resp.as_bytes()).await?;
		sock.write_all(INFO.as_bytes()).await?;
		return Ok(());
	};
	if request_len != data_len {
		let resp = "HTTP/1.1 400 Bad Request\r\n\
                    Connection: close\r\n\
                    Content-Type: text/plain\r\n\r\n";
		sock.write_all(resp.as_bytes()).await?;
		return Ok(());
	}
	let accept = compute_accept_key(key_header);
	let response = format!(
		"HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
	);
	sock.write_all(response.as_bytes()).await?;

	let path = request.path.unwrap();
	let (path, _query) = path.split_once("?").unwrap_or((path, ""));
	let final_segment = path.rsplit_once("/").map(|(_, end)| end).unwrap_or(path);
	let upstream_addr = parse_upstream_addr(&percent_decode_str(final_segment).decode_utf8_lossy());
	if policy.allowed_upstreams.as_ref().is_some_and(|x| {
		!x.split(",").map(str::trim).any(|x| parse_upstream_addr(x) == upstream_addr)
	}) {
		let mut buf = [0u8; _];
		const MESSAGE: &str = "upstream prohibited by proxy configuration";
		sock.write_all(close_frame(&mut buf, 1000, MESSAGE)).await?;
		return Ok(());
	}
	let mut upstream = match TcpStream::connect(upstream_addr).await {
		Ok(upstream) => upstream,
		Err(e) => {
			let mut buf = [0u8; _];
			sock.write_all(close_frame(&mut buf, 1000, e)).await?;
			return Ok(());
		}
	};

	let (mut sock_r, sock_w) = sock.split();
	let (mut up_r, mut up_w) = upstream.split();
	let sock_w = Mutex::new(Some(sock_w));

	let _ = tokio::try_join!(
		forward_responses(&mut up_r, &sock_w),
		forward_requests(&mut sock_r, &sock_w, &mut up_w)
	);

	Ok(())
}

/// Forward traffic from an upstream DNS server to a WebSocket client.
async fn forward_responses(
	up_r: &mut ReadHalf<'_>,
	sock_w: &Mutex<Option<WriteHalf<'_>>>,
) -> io::Result<()> {
	/// Size of the upstream-to-client working buffer: a maximum-size DNS
	/// message with its 2-byte length prefix (65537 bytes) plus the prefix
	/// area required by `dns_to_ws` (2 bytes per 128 bytes of input).
	const BUF_SIZE: usize = 65536 / 128 * 130 + 1;

	// Reserve the prefix area as required by `dns_to_ws`.
	let offset = BUF_SIZE / 130 * 2;
	let mut dns_buf = [0u8; BUF_SIZE];
	let mut dns_fill = offset;

	let close_msg = loop {
		let size = match up_r.read(&mut dns_buf[dns_fill..]).await {
			Ok(0) => break close_frame(dns_buf.first_chunk_mut().unwrap(), 1000, ""),
			Err(e) => break close_frame(dns_buf.first_chunk_mut().unwrap(), 1000, e),
			Ok(size) => size,
		};
		dns_fill += size;
		let (ws_len, end) = dns_to_ws(&mut dns_buf[..dns_fill], offset);
		if ws_len > 0
			&& let Some(sock_w) = sock_w.lock().await.as_mut()
		{
			sock_w.write_all(&dns_buf[..ws_len]).await?;
		}
		let trailer_len = dns_fill - end;
		dns_buf.copy_within(end..dns_fill, offset);
		dns_fill = offset + trailer_len;
	};

	if let Some(mut sock_w) = sock_w.lock().await.take() {
		sock_w.write_all(close_msg).await?;
	}

	Ok(())
}

/// Forward traffic from a WebSocket client to an upstream DNS server.
async fn forward_requests(
	sock_r: &mut ReadHalf<'_>,
	sock_w: &Mutex<Option<WriteHalf<'_>>>,
	up_w: &mut WriteHalf<'_>,
) -> io::Result<()> {
	// fits maximum sized message, 2 header bytes, 2 extended length bytes, and
	// 4 mask bytes
	let mut ws_buf = [0u8; 65535 + 8];
	let mut ws_fill = 0usize;

	// fits maximum sized message with 2 header bytes
	let mut dns_buf = [0u8; 65535 + 2];
	let mut dns_pos = 0;

	// When ws_to_dns stops because the output buffer `dns_buf` is full,
	// the next iteration needs to rerun ws_to_dns with more space in
	// the output buffer without reading new data.
	let mut read = true;

	let code = loop {
		if read {
			let size @ 1.. = sock_r.read(&mut ws_buf[ws_fill..]).await? else {
				break 1000;
			};
			ws_fill += size;
		}
		let (dns_complete, dns_end, pong, ws_pos) =
			match ws_to_dns(&mut ws_buf[..ws_fill], &mut dns_buf, dns_pos) {
				Ok(state) => state,
				Err(code) => break code,
			};
		if dns_complete > 0 {
			if up_w.write_all(&dns_buf[..dns_complete]).await.is_err() {
				break 1000;
			}
		}
		if pong > 0
			&& let Some(sock_w) = sock_w.lock().await.as_mut()
		{
			sock_w.write_all(&ws_buf[..pong]).await?;
		}
		dns_buf.copy_within(dns_complete..dns_end, 0);
		dns_pos = dns_end - dns_complete;
		ws_buf.copy_within(ws_pos..ws_fill, 0);
		ws_fill -= ws_pos;
		read = ws_fill == 0 || dns_complete == 0;
	};

	if let Some(mut sock_w) = sock_w.lock().await.take() {
		let close_msg = close_frame(dns_buf.first_chunk_mut().unwrap(), code, "");
		sock_w.write_all(close_msg).await?;
	}

	Err(io::ErrorKind::UnexpectedEof.into())
}

/// Normalizes the final path segment into a `host:port` string suitable for
/// `TcpStream::connect`, defaulting the port to 53 if the argument doesn't
/// already specify one.
fn parse_upstream_addr(s: &str) -> String {
	if !s.contains(':') || s.ends_with(']') { format!("{s}:53") } else { s.into() }
}

/// Checks if a value is contained in a multi-valued HTTP header.
fn contains_val(value: &[u8], needle: &[u8]) -> bool {
	value.split(|&c| c == b',').any(|v| v.trim_ascii().eq_ignore_ascii_case(needle))
}

/// Returns the `Sec-WebSocket-Key` header value if the parsed request is
/// a valid HTTP/1.1 WebSocket upgrade request (RFC 6455 section 4.2.1),
/// or `None` otherwise.
fn websocket_key<'a>(req: &'a httparse::Request) -> Option<&'a str> {
	let (mut upgrade, mut connection, mut version) = (false, false, false);
	let mut key = None;

	for h in req.headers.iter() {
		if h.name.eq_ignore_ascii_case("upgrade") {
			upgrade |= contains_val(h.value, b"websocket");
		} else if h.name.eq_ignore_ascii_case("connection") {
			connection |= contains_val(h.value, b"upgrade");
		} else if h.name.eq_ignore_ascii_case("sec-websocket-version") {
			version = h.value.trim_ascii().eq_ignore_ascii_case(b"13");
		} else if h.name.eq_ignore_ascii_case("sec-websocket-key") {
			key = std::str::from_utf8(h.value).ok();
		}
	}

	key.filter(|_| upgrade && connection && version)
}

/// Computes the `Sec-WebSocket-Accept` header value for a given
/// `Sec-WebSocket-Key`, per RFC 6455 section 1.3.
fn compute_accept_key(key: &str) -> String {
	let mut hasher = Sha1::new();
	hasher.update(key.as_bytes());
	hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
	Base64::encode_string(&hasher.finalize())
}
