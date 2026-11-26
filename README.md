# xmip-core-transport-syslog

Syslog transport: one RFC 5424 message is one Stream, the header in the origin; UDP datagrams or TCP with octet counting. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location sends datagrams from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket. Over TCP it keeps one connection per collector (`transport::Pool`), message after message; until 2026-10-21 every send opened a connection of its own.

A Receive Location keeps what it binds for its carrier as its transport is opened (`Configured::listening`; on its first receive until 2026-11-16), the datagram socket or the listener: what arrives between two receives waits for the next, where until 2026-09-27 each receive bound its own and what came between was lost or refused. Over TCP it keeps its senders' connections beside the listener (`transport::serving::Serving`, `src/connection.rs`), and each framed message is one receive's turn, from whichever sender sends first; until 2026-10-21 a receive read one connection until its sender closed, which a sender that keeps its connection would never do.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls. Until 2026-09-28 this technology stripped its scheme by hand.

## Acknowledgement

Acceptance is at-most-once here. Neither carrier answers a message: a datagram
has nobody to answer, and RFC 6587 over TCP has no acknowledgement either, so
the sender is never told how the receive cycle ended and a crash before the
Stream is durable loses it. Each message arrives whole, one a receive; what
a sender sent meanwhile waits in this side's socket for the next receive.

## The declaration

What a Location of this technology is configured with is two `const`s in its
`declaration` module, `src/declaration.rs`, beside the code, which
`Configured` reads (ADR-0064, amendment 2026-11-26):
`declaration::SETTINGS`, `carrier`, `hostname`, `app_name`, `facility`,
`severity` and `timeout`, and `SCHEMES`, `syslog` and `syslog+tcp`. The
facility and the severity a wrapped payload is sent under unless told
otherwise, `FACILITY` and `SEVERITY`, are there too, and the code reads them
from there. Built with its `declaration` feature alone
(`--no-default-features --features declaration`), the crate is those and
nothing more: its code and every crate the code is built on are behind the
default feature. So the library the surfaces load can carry it without the
code, for the language server and the desktop to suggest and check a syslog
Location's settings though no node in their process loaded the technology,
once the gathering crate of open problem 48 links it.
`test/Declaration.Test.ps1` in the estate holds that the declaration builds
nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
