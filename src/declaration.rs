//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// The facility a wrapped payload is sent under unless told otherwise: 16,
/// local0.
pub const FACILITY: u8 = 16;
/// The severity a wrapped payload is sent under unless told otherwise: 6,
/// informational.
pub const SEVERITY: u8 = 6;

/// Every setting a Location takes beyond its address, which is where a
/// Receive Location listens; a Send Location's collector is each send's
/// target. The header a wrapped payload is sent under is read from these,
/// never parsed from the target.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "carrier",
            kind: Kind::Choice {
                choices: &["udp", "tcp"],
            },
            presence: Presence::Optional,
            meaning: "UDP datagrams, or TCP with octet counting; UDP when left out.",
            applies: Applies::Both,
        },
        Setting {
            name: "hostname",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The HOSTNAME a wrapped payload's header names this node by.",
            applies: Applies::Send,
        },
        Setting {
            name: "app_name",
            kind: Kind::Text,
            presence: Presence::Default(Fixed::Text("xmip")),
            meaning: "The APP-NAME a wrapped payload's header names.",
            applies: Applies::Send,
        },
        Setting {
            name: "facility",
            kind: Kind::Integer {
                minimum: 0,
                maximum: 23,
            },
            presence: Presence::Default(Fixed::Integer(FACILITY as i64)),
            meaning: "The facility a wrapped payload is sent under.",
            applies: Applies::Send,
        },
        Setting {
            name: "severity",
            kind: Kind::Integer {
                minimum: 0,
                maximum: 7,
            },
            presence: Presence::Default(Fixed::Integer(SEVERITY as i64)),
            meaning: "The severity a wrapped payload is sent under.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a message or a connection is waited for; unbounded when left \
             out.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["syslog", "syslog+tcp"];
