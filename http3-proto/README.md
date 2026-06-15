# http3-proto

Sans-I/O state machine for the HTTP/3 Extended-CONNECT *tunnel* — the subset of
HTTP/3 (RFC 9114 / 9204 / 9220) needed to carry a tunneled byte protocol (e.g.
WebSocket) over QUIC. Transport-blind, `no_std` + no-alloc capable, panic-free
codec leaf. The protocol core under `wren-h3`.
