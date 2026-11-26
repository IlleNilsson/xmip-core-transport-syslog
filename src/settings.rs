//! The one way a syslog transport is built from the settings its
//! declaration names (`crate::declaration`; ADR-0064, amendments 2026-09-26
//! and 2026-11-26).

use transport::Configured;
use transport::error::{Result, protocol_error};
use xcore::settings::{Read, Settings};

use crate::declaration::{self, FACILITY, SEVERITY};
use crate::{Carrier, SyslogTransport};

impl Configured for SyslogTransport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

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
        Ok(transport)
    }

    /// Each TCP sender's turn on a Receive Location taking at most `turn`.
    fn turning_within(mut self, turn: std::time::Duration) -> Self {
        self.connections = self.connections.turning_within(turn);
        self
    }

    /// Each callers turn on a Receive Location counted on clock.
    fn timed_by(mut self, clock: &std::sync::Arc<dyn xcore::Clock>) -> Self {
        self.connections = self.connections.timed_by(clock);
        self
    }

    /// What every receive takes from, bound where a Receive Location
    /// listens on its carrier: a datagram socket, or a listener over TCP.
    fn listening(&self) -> Result<Option<&str>> {
        match self.carrier {
            Carrier::Udp => self.datagrams.listening(|| self.bind_udp()),
            Carrier::Tcp => self.connections.bound(|| self.bind_tcp()).map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use xcore::settings::{Applies, Given};

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
