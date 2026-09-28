# xmip-core-transport-syslog

Syslog transport: one RFC 5424 message is one Stream, the header in the origin; UDP datagrams or TCP with octet counting. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location sends from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps what it binds for its carrier on the first receive (`transport::kept::Kept`), the datagram socket or the listener: what arrives between two receives waits for the next, where until 2026-09-27 each receive bound its own and what came between was lost or refused.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls. Until 2026-09-28 this technology stripped its scheme by hand.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
