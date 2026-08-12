// SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end integration tests for the DoWS proxy.
//!
//! Each test starts a tiny in-process DNS over TCP server on a random port,
//! spawns the compiled `dows` proxy binary (which prints its own listening
//! address on startup), and then talks to the DNS server through the proxy
//! using a real WebSocket client (`tokio-tungstenite`).
//!
//! The proxy treats the DNS payload as opaque bytes and only cares about the
//! 2-byte big-endian length prefix used by DNS over TCP (RFC 1035 §4.2.2), so
//! the test server implements just that framing rather than pulling in a full
//! DNS stack.

use std::{
	io::{BufRead, BufReader},
	net::{Ipv6Addr, SocketAddr},
	process::{Child, Command, Stdio},
};

use futures_util::{SinkExt, StreamExt};
use nix::{
	sys::signal::{Signal, kill},
	unistd::Pid,
};
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, TcpStream},
	task::{JoinHandle, JoinSet},
};
use tokio_tungstenite::{
	connect_async,
	tungstenite::{Message as WsMessage, protocol::frame::coding::CloseCode},
};

/// Terminates the spawned proxy process when the test finishes (or
/// panics).
///
/// The proxy is asked to exit cleanly with SIGTERM instead of SIGKILL so
/// that its exit hooks run; coverage instrumentation relies on those to
/// write the profile data of the child process. SIGKILL is the fallback
/// in case the proxy fails to shut down on its own.
struct ChildGuard(Child);

impl Drop for ChildGuard {
	fn drop(&mut self) {
		let pid = Pid::from_raw(self.0.id().try_into().expect("pid fits into i32"));
		let _ = kill(pid, Signal::SIGTERM);
		let terminated = std::iter::repeat_with(|| {
			std::thread::sleep(std::time::Duration::from_millis(10));
			self.0.try_wait()
		})
		.take(500)
		.any(|status| !matches!(status, Ok(None)));
		if !terminated {
			let _ = self.0.kill();
			let _ = self.0.wait();
		}
	}
}

/// A running proxy + DNS server, with the WebSocket URL to reach the DNS
/// server through the proxy.
struct Harness {
	dns_server: JoinHandle<()>,
	dns_endpoint: SocketAddr,
	proxy_endpoint: String,
	ws_base: String,
	_child: ChildGuard,
}

impl Harness {
	async fn start() -> Self {
		// Start the DNS server on a random TCP port.
		let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
		let dns_endpoint = listener.local_addr().unwrap();
		let dns_server = tokio::spawn(run_dns_server(listener));

		// Spawn the proxy binary, letting the OS pick the port. The proxy prints
		// its actual listening address on the first line of stdout.
		let mut child = Command::new(env!("CARGO_BIN_EXE_dows"))
			.arg("[::1]:0")
			.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.spawn()
			.expect("spawn dows proxy binary");

		let mut stdout = BufReader::new(child.stdout.take().expect("capture proxy stdout"));
		let mut line = String::new();
		let endpoint = loop {
			line.clear();
			stdout.read_line(&mut line).expect("read proxy address");
			if let Some(endpoint) = line.strip_prefix("listening on ") {
				break endpoint.trim().to_owned();
			}
		};

		Self {
			dns_endpoint,
			ws_base: format!("ws://{endpoint}"),
			proxy_endpoint: endpoint,
			dns_server,
			_child: ChildGuard(child),
		}
	}

	fn ws_url(&self) -> String {
		format!("{}/{}", self.ws_base, self.dns_endpoint)
	}
}

/// A minimal DNS over TCP server: for every length-prefixed query it replies
/// with a length-prefixed response (all-zero except the echoed transaction ID
/// and the QR bit).
async fn run_dns_server(listener: TcpListener) {
	// Aborting the server task drops this set, which in turn cancels all
	// connection tasks and closes their sockets.
	let mut connections = JoinSet::new();
	while let Ok((mut sock, _)) = listener.accept().await {
		connections.spawn(async move {
			let mut len = [0; 2];
			while sock.read_exact(&mut len).await.is_ok() {
				let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
				sock.read_exact(&mut query).await?;
				let Some([a, b]) = query.first_chunk().copied() else {
					break;
				};
				sock.write_all(&[0, 12, a, b, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]).await?;
			}
			std::io::Result::Ok(())
		});
	}
}

/// Sends a raw HTTP request to the proxy and returns the response as text,
/// reading until the proxy closes the connection.
async fn raw_http_request(proxy_endpoint: &str, request: &str) -> String {
	let mut sock = TcpStream::connect(proxy_endpoint).await.expect("connect to proxy");
	sock.write_all(request.as_bytes()).await.expect("send request");
	let mut response = Vec::new();
	sock.read_to_end(&mut response).await.expect("read response");
	String::from_utf8(response).expect("response should be valid UTF-8")
}

#[tokio::test]
async fn single_query_is_proxied_to_dns() {
	let harness = Harness::start().await;
	let (mut ws, _resp) = connect_async(&harness.ws_url()).await.expect("websocket handshake");

	let query: &[u8] = &[0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	ws.send(WsMessage::Binary(query.into())).await.expect("send query");

	let reply = ws.next().await.transpose().expect("low level errors not expected");
	let Some(WsMessage::Binary(response)) = reply else {
		panic!("expected a binary DNS response, got {reply:?}");
	};

	assert_eq!(&response[0..2], &[0x12, 0x34], "response should echo the query ID");
	assert_eq!(response[2] & 0x80, 0x80, "QR bit should mark this as a response");

	ws.close(None).await.expect("close websocket");
}

#[tokio::test]
async fn maximum_size_query_is_proxied_to_dns() {
	let harness = Harness::start().await;
	let (mut ws, _resp) = connect_async(&harness.ws_url()).await.expect("websocket handshake");

	// The largest message DNS over TCP can carry: the 2-byte big-endian
	// length prefix caps a message at 65535 bytes.
	let mut query = vec![0; 65535];
	query[0] = 0xAB;
	query[1] = 0xCD;
	ws.send(WsMessage::Binary(query.into())).await.expect("send query");

	let reply = ws.next().await.transpose().expect("low level errors not expected");
	let Some(WsMessage::Binary(response)) = reply else {
		panic!("expected a binary DNS response, got {reply:?}");
	};

	assert_eq!(&response[0..2], &[0xAB, 0xCD], "response should echo the query ID");
	assert_eq!(response[2] & 0x80, 0x80, "QR bit should mark this as a response");

	ws.close(None).await.expect("close websocket");
}

#[tokio::test]
async fn ping_is_answered_with_pong() {
	let harness = Harness::start().await;
	let (mut ws, _resp) = connect_async(&harness.ws_url()).await.expect("websocket handshake");

	let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
	ws.send(WsMessage::Ping(payload.clone().into())).await.expect("send ping");

	let reply = ws.next().await.transpose().expect("low level errors not expected");
	let Some(WsMessage::Pong(pong)) = reply else {
		panic!("expected a pong, got {reply:?}");
	};
	assert_eq!(pong.as_ref(), payload.as_slice());

	ws.close(None).await.expect("close websocket");
}

#[tokio::test]
async fn clean_closure_is_handled() {
	let harness = Harness::start().await;
	let (mut ws, _resp) = connect_async(&harness.ws_url()).await.expect("websocket handshake");

	// Initiate a clean closing handshake.
	ws.close(None).await.expect("send close");

	// The proxy should reply with a Close frame and then let the stream end,
	// without any protocol error.
	let mut saw_close = false;
	while let Some(message) = ws.next().await.transpose().expect("low level errors not expected") {
		if message.is_close() {
			saw_close = true;
		}
	}
	assert!(saw_close, "expected the proxy to echo a Close frame");
}

#[tokio::test]
async fn invalid_upstream_returns_close_with_reason() {
	let harness = Harness::start().await;
	// Port 0 is not a connectable endpoint, so the proxy will fail to reach it.
	let url = format!("{}/localhost:0", harness.ws_base);
	let (mut ws, _resp) = connect_async(&url).await.expect("websocket handshake");

	// The upgrade succeeds, then the proxy reports the upstream failure with a
	// Close frame that carries a code and a non-empty reason.
	let reply = ws.next().await.transpose().expect("low level errors not expected");
	let Some(WsMessage::Close(frame)) = reply else {
		panic!("expected a close frame, got {reply:?}");
	};
	let frame = frame.expect("close frame should include a code and reason");
	assert!(!frame.reason.as_str().is_empty(), "close reason should not be empty");
}

#[tokio::test]
async fn root_path_returns_info_page() {
	let harness = Harness::start().await;
	let response =
		raw_http_request(&harness.proxy_endpoint, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
			.await;

	assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "unexpected response: {response}");
	assert!(
		response.contains(concat!("\r\n\r\n", env!("CARGO_PKG_NAME"))),
		"body should start with the package name: {response}"
	);
}

#[tokio::test]
async fn non_upgrade_request_returns_upgrade_required() {
	let harness = Harness::start().await;
	let response = raw_http_request(
		&harness.proxy_endpoint,
		&format!("GET /{} HTTP/1.1\r\nHost: localhost\r\n\r\n", harness.dns_endpoint),
	)
	.await;

	assert!(
		response.starts_with("HTTP/1.1 426 Upgrade Required\r\n"),
		"unexpected response: {response}"
	);
	assert!(
		response.contains("\r\nUpgrade: websocket\r\n"),
		"response should advertise the websocket upgrade: {response}"
	);
}

#[tokio::test]
async fn upgrade_request_with_body_returns_bad_request() {
	let harness = Harness::start().await;
	// A well-formed upgrade request, but with stray body bytes after the
	// header section. GET requests have no body, and any pipelined data
	// before the connection switches protocols is bogus.
	let response = raw_http_request(
		&harness.proxy_endpoint,
		&format!(
			"GET /{} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n\
             bogus",
			harness.dns_endpoint
		),
	)
	.await;

	assert!(
		response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
		"unexpected response: {response}"
	);
}

#[tokio::test]
async fn upstream_closure_returns_clean_close_frame() {
	let harness = Harness::start().await;
	let (mut ws, _resp) = connect_async(&harness.ws_url()).await.expect("websocket handshake");

	// Complete one round trip so the proxy's upstream connection is
	// established before the DNS server goes away.
	let query: &[u8] = &[0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	ws.send(WsMessage::Binary(query.into())).await.expect("send query");
	let reply = ws.next().await.transpose().expect("low level errors not expected");
	assert!(matches!(reply, Some(WsMessage::Binary(_))), "expected a DNS response, got {reply:?}");

	// Kill the DNS server; dropping its JoinSet cancels the connection
	// tasks, closing the proxy's upstream socket.
	harness.dns_server.abort();

	// The proxy should report the closed upstream with a clean Close frame.
	let reply = ws.next().await.transpose().expect("low level errors not expected");
	let Some(WsMessage::Close(frame)) = reply else {
		panic!("expected a close frame, got {reply:?}");
	};
	let frame = frame.expect("close frame should include a code");
	assert_eq!(frame.code, CloseCode::Normal);
}
