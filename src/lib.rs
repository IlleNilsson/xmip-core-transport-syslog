#![forbid(unsafe_code)]

//! Streams that arrive as syslog messages. One message is one Stream: the
//! RFC 5424 header is addressing and travels in the origin URI, and MSG —
//! what the application had to say — is what Xmip carries.
//!
//! Syslog is the operations floor's protocol: every server, switch and
//! appliance speaks it, over UDP on port 514 or TCP with octet counting (RFC
//! 6587). A Receive Location listens and takes what the estate reports; a
//! Send Location writes what a Journey concluded to the collector everything
//! else already goes to. A payload that is already a syslog message is sent
//! as it is; any other is wrapped in a header naming this node.
//!
//! The origin URI carries what the header knew:
//! `syslog://peer?facility=16&severity=6&host=edge-01&app=xmip&msgid=-`.

pub mod message;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

pub use message::Header;
use transport::error::{Result, classify, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// The largest datagram a syslog receiver must take, RFC 5426.
pub const MAX_DATAGRAM: usize = 65_535;
/// The most an octet-counted frame may say before it is refused.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// UDP datagrams, or TCP with octet counting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Udp,
    Tcp,
}

#[derive(Clone)]
pub struct SyslogTransport {
    bind: String,
    carrier: Carrier,
    hostname: String,
    app_name: String,
    facility: u8,
    severity: u8,
    timeout: Option<Duration>,
}

impl SyslogTransport {
    /// Listen at `bind` over UDP; `0.0.0.0:514` is the standard port.
    /// Messages sent name `hostname` and `app_name`, facility 16 (local0),
    /// severity 6 (informational).
    #[must_use]
    pub fn new(bind: impl Into<String>, hostname: &str, app_name: &str) -> Self {
        Self {
            bind: bind.into(),
            carrier: Carrier::Udp,
            hostname: hostname.to_string(),
            app_name: app_name.to_string(),
            facility: 16,
            severity: 6,
            timeout: None,
        }
    }

    /// Over TCP with octet counting rather than UDP.
    #[must_use]
    pub const fn over(mut self, carrier: Carrier) -> Self {
        self.carrier = carrier;
        self
    }

    /// The facility and severity a wrapped payload is sent under.
    #[must_use]
    pub const fn as_priority(mut self, facility: u8, severity: u8) -> Self {
        self.facility = facility;
        self.severity = severity;
        self
    }

    /// Give up waiting for a message after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind the UDP socket and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind_udp(&self) -> Result<(UdpSocket, String)> {
        socket::bind_udp(&self.bind, self.timeout)
    }

    /// Take one message from an already-bound socket.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not RFC 5424.
    pub fn receive_datagram(&self, socket: &UdpSocket) -> Result<Arrived> {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let (read, peer) = socket
            .recv_from(&mut buffer)
            .map_err(|e| classify("receiving a datagram", &e))?;
        arrived(peer, &buffer[..read])
    }

    /// Bind the TCP listener and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind_tcp(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.bind)
    }

    /// Accept one sender on an already-bound listener.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Connection> {
        let (stream, peer) = socket::accept_tcp(listener, self.timeout)?;
        Ok(Connection {
            reader: BufReader::new(stream),
            peer,
        })
    }

    /// `bytes` as a syslog message: as they are when they already are one,
    /// else wrapped in a header naming this node.
    #[must_use]
    pub fn compose(&self, bytes: &[u8]) -> Vec<u8> {
        if bytes.starts_with(b"<") && message::parse(bytes).is_ok() {
            return bytes.to_vec();
        }
        let header = Header::now(self.facility, self.severity, &self.hostname, &self.app_name);
        message::format(&header, bytes)
    }
}

/// One TCP sender's messages, octet-counted or newline-terminated, RFC 6587.
pub struct Connection {
    reader: BufReader<TcpStream>,
    peer: SocketAddr,
}

impl Connection {
    /// The next message, or `None` when the sender closed between messages.
    ///
    /// # Errors
    /// A frame that breaks off, a count over [`MAX_FRAME`], or a message that
    /// is not RFC 5424.
    pub fn next_message(&mut self) -> Result<Option<Arrived>> {
        let first = match self.reader.fill_buf() {
            Ok([]) => return Ok(None),
            Ok(buffer) => buffer[0],
            Err(error) => return Err(classify("reading a frame", &error)),
        };
        let raw = if first.is_ascii_digit() {
            let mut count = Vec::new();
            self.reader
                .read_until(b' ', &mut count)
                .map_err(|e| classify("reading the octet count", &e))?;
            let count: usize = std::str::from_utf8(&count)
                .ok()
                .and_then(|c| c.trim().parse().ok())
                .ok_or_else(|| protocol_error("an octet count that is not a number"))?;
            if count > MAX_FRAME {
                return Err(protocol_error("an octet count over what Xmip will read"));
            }
            let mut raw = vec![0u8; count];
            self.reader
                .read_exact(&mut raw)
                .map_err(|e| classify("reading the message", &e))?;
            raw
        } else {
            let mut raw = Vec::new();
            self.reader
                .read_until(b'\n', &mut raw)
                .map_err(|e| classify("reading the message", &e))?;
            while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                raw.pop();
            }
            raw
        };
        arrived(self.peer, &raw).map(Some)
    }
}

fn arrived(peer: SocketAddr, raw: &[u8]) -> Result<Arrived> {
    let (header, msg) = message::parse(raw)?;
    Ok(Arrived::new(
        format!(
            "syslog://{peer}?facility={}&severity={}&host={}&app={}&msgid={}",
            header.facility, header.severity, header.hostname, header.app_name, header.msg_id
        ),
        msg,
    ))
}

impl Transport for SyslogTransport {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// One datagram, or one TCP sender's messages until it closes.
    fn receive(&self) -> Result<Vec<Arrived>> {
        match self.carrier {
            Carrier::Udp => {
                let (socket, _) = self.bind_udp()?;
                Ok(vec![self.receive_datagram(&socket)?])
            }
            Carrier::Tcp => {
                let (listener, _) = self.bind_tcp()?;
                let mut connection = self.accept_one(&listener)?;
                let mut arrived = Vec::new();
                while let Some(message) = connection.next_message()? {
                    arrived.push(message);
                }
                Ok(arrived)
            }
        }
    }

    /// To `syslog://host:514`, `syslog+tcp://host:514`, or `host:port` over
    /// the configured carrier.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (carrier, address) = if let Some(rest) = target.strip_prefix("syslog+tcp://") {
            (Carrier::Tcp, rest)
        } else if let Some(rest) = target.strip_prefix("syslog://") {
            (Carrier::Udp, rest)
        } else {
            (self.carrier, target)
        };
        let message = self.compose(bytes);
        match carrier {
            Carrier::Udp => {
                if message.len() > MAX_DATAGRAM {
                    return Err(protocol_error("a message over what a datagram carries"));
                }
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .map_err(|e| classify("binding the sending socket", &e))?;
                socket
                    .send_to(&message, address)
                    .map_err(|e| classify("sending the datagram", &e))?;
                Ok(())
            }
            Carrier::Tcp => {
                let mut stream = TcpStream::connect(address)
                    .map_err(|e| classify("connecting to the collector", &e))?;
                let mut frame = format!("{} ", message.len()).into_bytes();
                frame.extend_from_slice(&message);
                stream
                    .write_all(&frame)
                    .map_err(|e| classify("writing the frame", &e))?;
                stream
                    .flush()
                    .map_err(|e| classify("flushing the frame", &e))
            }
        }
    }
}

impl SyslogTransport {
    /// Both ends on this machine: a collector over TCP with octet counting
    /// on an ephemeral local port — the carrier that holds a megabyte; the
    /// datagram carrier is the one bound by default and it is exercised in
    /// the tests — with the loopback timeout on the accept.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", "loopback", "xmip")
            .over(Carrier::Tcp)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound collector waiting for its one sender's one message.
struct Listening {
    transport: SyslogTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut connection = self.transport.accept_one(&self.listener)?;
        connection
            .next_message()?
            .ok_or_else(|| protocol_error("the sender closed without a message"))
    }
}

impl Loopback for SyslogTransport {
    /// A payload that already is a syslog message is sent as it is, and what
    /// arrives is its MSG: the header is the origin, never the Stream.
    fn refuses(&self, payload: &[u8]) -> Option<String> {
        (payload.starts_with(b"<") && message::parse(payload).is_ok()).then(|| {
            "already a syslog message: sent as it is, and its MSG is what arrives".to_string()
        })
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind_tcp()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new("127.0.0.1:0", &self.hostname, &self.app_name)
            .send(&format!("syslog+tcp://{address}"), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> SyslogTransport {
        SyslogTransport::new("127.0.0.1:0", "edge-01", "xmip")
            .timing_out_after(Duration::from_secs(2))
    }

    /// The shapes a transport is most likely to change: nothing, one byte,
    /// every byte value, a run of NULs, high bytes, and line endings alone.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_carries_a_stream_as_one_counted_message() {
        let collector = SyslogTransport::loopback();
        let arrived = collector.round(b"counted\nwith newline").expect("round");
        assert_eq!(arrived.bytes, b"counted\nwith newline");
        assert!(arrived.origin_uri.starts_with("syslog://127.0.0.1:"));
        assert!(
            arrived
                .origin_uri
                .contains("facility=16&severity=6&host=loopback&app=xmip")
        );
        let long = vec![0x2a; 100_000];
        assert_eq!(collector.round(&long).expect("long").bytes, long);
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole_and_refuses_a_message() {
        let collector = SyslogTransport::loopback();
        assert!(collector.ceiling().is_none());
        for (name, bytes) in edge_payloads() {
            assert!(collector.refuses(&bytes).is_none(), "{name}");
            assert_eq!(collector.round(&bytes).expect(name).bytes, bytes, "{name}");
        }
        // A declared refusal is true: a message goes as it is and its MSG
        // is what comes back.
        let already = b"<13>1 - other app - - - already";
        assert!(collector.refuses(already).is_some());
        assert_eq!(collector.round(already).expect("as-is").bytes, b"already");
    }

    #[test]
    fn a_datagram_carries_the_payload_and_the_header_is_the_origin() {
        let far_end = node();
        let (socket, address) = far_end.bind_udp().expect("binding");
        node()
            .send(&format!("syslog://{address}"), b"ping\r\npong")
            .expect("sending");
        let arrived = far_end.receive_datagram(&socket).expect("receiving");
        assert_eq!(arrived.bytes, b"ping\r\npong");
        assert!(
            arrived
                .origin_uri
                .contains("facility=16&severity=6&host=edge-01&app=xmip")
        );
        node()
            .send(&address, b"<13>1 - other app - - - already")
            .expect("as-is");
        let arrived = far_end.receive_datagram(&socket).expect("receiving");
        assert_eq!(arrived.bytes, b"already");
        assert!(arrived.origin_uri.contains("severity=5&host=other&app=app"));
    }

    #[test]
    fn a_tcp_sender_frames_by_octet_count_or_by_line() {
        let far_end = node().over(Carrier::Tcp);
        let (listener, address) = far_end.bind_tcp().expect("binding");
        let mut stream = TcpStream::connect(&address).expect("connecting");
        let counted = b"<34>1 - - - - - - counted\nwith newline";
        stream
            .write_all(format!("{} ", counted.len()).as_bytes())
            .expect("writing the count");
        stream.write_all(counted).expect("writing the counted");
        stream
            .write_all(b"<34>1 - - - - - - line one\n<34>1 - - - - - - line two\r\n")
            .expect("writing the lines");
        drop(stream);
        let mut connection = far_end.accept_one(&listener).expect("accepting");
        let first = connection.next_message().expect("first").expect("one");
        let one = connection.next_message().expect("one").expect("one");
        let two = connection.next_message().expect("two").expect("two");
        assert_eq!(first.bytes, b"counted\nwith newline");
        assert_eq!(one.bytes, b"line one");
        assert_eq!(two.bytes, b"line two");
        assert!(connection.next_message().expect("closed").is_none());
    }

    #[test]
    fn what_is_not_syslog_is_refused_and_nothing_is_claimed() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut stream = TcpStream::connect(listener.local_addr().expect("address")).expect("c");
        stream.write_all(b"x hello\n").expect("writing");
        let mut connection = node().accept_one(&listener).expect("accepting");
        assert!(!connection.next_message().expect_err("refused").retryable);
        assert!(node().claims().is_none());
        assert_eq!(node().name(), "syslog");
    }
}
