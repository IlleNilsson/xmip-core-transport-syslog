# xmip-core-transport-syslog

Syslog transport: one RFC 5424 message is one Stream, the header in the origin; UDP datagrams or TCP with octet counting. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
