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

The only command line argument is the optional listener address. To restrict the
allowed upstreams and origins, `DOWS_ALLOWED_UPSTREAMS` and
`DOWS_ALLOWED_ORIGINS` must be set to comma-separated lists of allowed values.
Alternatively, both of these variables can be set exactly to `*` (allow any),
which disables the specific check.
