//! The settings a syslog Location takes, and the one way a transport is
//! built from them (ADR-0064, amendment 2026-09-26).

use transport::Configured;
use transport::error::{Result, protocol_error};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

use crate::{Carrier, FACILITY, SEVERITY, SyslogTransport};

impl Configured for SyslogTransport {
    /// The address is where a Receive Location listens; a Send Location's
    /// collector is each send's target. The header a wrapped payload is sent
    /// under is read here, never parsed from the target.
    const SETTINGS: &'static Settings = &Settings {
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
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a message or a connection is waited for; unbounded when left \
                          out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        // A Receive Location reads no header: it names nothing it sends.
        let mut transport = SyslogTransport::new(
            address,
            settings.optional_text("hostname").unwrap_or_default(),
            settings.optional_text("app_name").unwrap_or_default(),
        );
        if settings.optional_text("carrier") == Some("tcp") {
            transport = transport.over(Carrier::Tcp);
        }
        // A Send Location's defaults are filled in; a Receive Location's are
        // the constructor's own, since it sends nothing.
        let priority = |name, held: u8| {
            settings.optional_integer(name).map_or(Ok(held), |value| {
                u8::try_from(value).map_err(|_| protocol_error("a priority out of range"))
            })
        };
        let facility = priority("facility", FACILITY)?;
        let severity = priority("severity", SEVERITY)?;
        transport = transport.as_priority(facility, severity);
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use xcore::settings::Given;

    #[test]
    fn syslog_declares_its_settings_and_reads_through_them() {
        assert_eq!(SyslogTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("carrier".to_string(), Given::Text("tcp".to_string())),
            ("hostname".to_string(), Given::Text("edge-01".to_string())),
            ("severity".to_string(), Given::Integer(3)),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let built = SyslogTransport::open("0.0.0.0:514", Applies::Send, &given).expect("built");
        assert_eq!(built.carrier, Carrier::Tcp);
        assert_eq!(
            (built.hostname.as_str(), built.app_name.as_str()),
            ("edge-01", "xmip")
        );
        assert_eq!((built.facility, built.severity), (FACILITY, 3));
        assert_eq!(built.timeout, Some(Duration::from_secs(2)));
        let received = SyslogTransport::open("0.0.0.0:514", Applies::Receive, &[]).expect("r");
        assert_eq!(received.carrier, Carrier::Udp);
        let Err(refused) = SyslogTransport::open("0.0.0.0:514", Applies::Send, &[]) else {
            panic!("a Send Location names its host");
        };
        assert!(refused.message.contains("hostname"), "{}", refused.message);
    }
}
