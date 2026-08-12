<!--
SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# dows (DNS over WebSocket proxy)

dows accepts DNS over WebSocket connections and proxies them to DNS servers over
TCP.

## Protocol

DNS over WebSocket is a transport for DNS messages. The proxy uses the last
segment (as in RFC 3986) of the WebSocket path as the target endpoint. The
target endpoint is encoded like an authority without userinfo (as in RFC 3986,
Section 3). Each DNS message (as in RFC 1035, Section 4.1) is the payload of a
WebSocket binary data message (as in RFC 6455).

## Usage

The only command line argument is the listener address.

If you expose this service publicly, you can restrict the allowed upstreams by
setting the environment variable `DOWS_ALLOWED_UPSTREAMS` to a comma-separated
list of allowed upstreams. Entries are normalized like path segments (URI
authority, percent-decoded, default port 53) before matching.
