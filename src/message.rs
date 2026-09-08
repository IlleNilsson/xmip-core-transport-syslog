//! RFC 5424: the header a syslog message opens with, read and written.
//!
//! `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [SP MSG]`
//! — PRI is facility times eight plus severity, every header field is `-`
//! when unknown, structured data is `-` or one or more `[id k="v"]` elements,
//! and MSG is whatever follows the one space after them. This file reads the
//! header and hands MSG back untouched; MSG is the Stream.

use std::time::{SystemTime, UNIX_EPOCH};

use transport::error::{Result, protocol_error};

/// Everything before MSG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub facility: u8,
    pub severity: u8,
    pub timestamp: String,
    pub hostname: String,
    pub app_name: String,
    pub proc_id: String,
    pub msg_id: String,
    /// `-`, or the elements as written.
    pub structured_data: String,
}

impl Header {
    /// A header from `hostname` and `app_name`, stamped now, the rest `-`.
    #[must_use]
    pub fn now(facility: u8, severity: u8, hostname: &str, app_name: &str) -> Self {
        Self {
            facility,
            severity,
            timestamp: timestamp_now(),
            hostname: nil_if_empty(hostname),
            app_name: nil_if_empty(app_name),
            proc_id: "-".to_string(),
            msg_id: "-".to_string(),
            structured_data: "-".to_string(),
        }
    }

    /// PRI as the wire writes it.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        (self.facility as u16) * 8 + (self.severity as u16 & 7)
    }
}

/// `header` and `msg` as one syslog message.
#[must_use]
pub fn format(header: &Header, msg: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "<{}>1 {} {} {} {} {} {}",
        header.priority(),
        header.timestamp,
        header.hostname,
        header.app_name,
        header.proc_id,
        header.msg_id,
        header.structured_data
    )
    .into_bytes();
    if !msg.is_empty() {
        out.push(b' ');
        out.extend_from_slice(msg);
    }
    out
}

/// Read one syslog message: the header, and MSG as the bytes that follow it.
///
/// # Errors
/// Not RFC 5424: no PRI, a version that is not 1, a header field missing,
/// or structured data that does not close.
pub fn parse(bytes: &[u8]) -> Result<(Header, &[u8])> {
    let rest = bytes
        .strip_prefix(b"<")
        .ok_or_else(|| protocol_error("a message that does not open with <PRI>"))?;
    let close = rest
        .iter()
        .position(|b| *b == b'>')
        .filter(|at| (1..=3).contains(at))
        .ok_or_else(|| protocol_error("a PRI that is not one to three digits"))?;
    let priority: u16 = std::str::from_utf8(&rest[..close])
        .ok()
        .and_then(|digits| digits.parse().ok())
        .filter(|p| *p <= 191)
        .ok_or_else(|| protocol_error("a PRI outside 0 to 191"))?;
    let rest = rest[close + 1..]
        .strip_prefix(b"1 ")
        .ok_or_else(|| protocol_error("a version that is not 1"))?;
    let mut at = 0usize;
    let mut fields = Vec::with_capacity(5);
    for name in ["TIMESTAMP", "HOSTNAME", "APP-NAME", "PROCID", "MSGID"] {
        let field = word(rest, &mut at)
            .ok_or_else(|| protocol_error(format!("a header without {name}")))?;
        fields.push(field);
    }
    let structured_data = structured_data(rest, &mut at)?;
    let msg = match rest.get(at) {
        None => &rest[rest.len()..],
        Some(b' ') => &rest[at + 1..],
        Some(_) => return Err(protocol_error("structured data not followed by a space")),
    };
    let text = |index: usize| String::from_utf8_lossy(fields[index]).into_owned();
    let facility = u8::try_from(priority / 8).unwrap_or(0);
    let severity = u8::try_from(priority % 8).unwrap_or(0);
    Ok((
        Header {
            facility,
            severity,
            timestamp: text(0),
            hostname: text(1),
            app_name: text(2),
            proc_id: text(3),
            msg_id: text(4),
            structured_data,
        },
        msg,
    ))
}

/// One space-terminated, non-empty header field.
fn word<'a>(rest: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let start = *at;
    let end = rest[start..].iter().position(|b| *b == b' ')? + start;
    if end == start {
        return None;
    }
    *at = end + 1;
    Some(&rest[start..end])
}

/// `-`, or every `[...]` element, quotes and escapes honoured.
fn structured_data(rest: &[u8], at: &mut usize) -> Result<String> {
    if rest.get(*at) == Some(&b'-') {
        *at += 1;
        return Ok("-".to_string());
    }
    let start = *at;
    while rest.get(*at) == Some(&b'[') {
        let mut quoted = false;
        let mut escaped = false;
        loop {
            let byte = *rest
                .get(*at)
                .ok_or_else(|| protocol_error("structured data that does not close"))?;
            *at += 1;
            match byte {
                _ if escaped => escaped = false,
                b'\\' if quoted => escaped = true,
                b'"' => quoted = !quoted,
                b']' if !quoted => break,
                _ => {}
            }
        }
    }
    if *at == start {
        return Err(protocol_error(
            "structured data that is neither - nor [element]",
        ));
    }
    Ok(String::from_utf8_lossy(&rest[start..*at]).into_owned())
}

fn nil_if_empty(value: &str) -> String {
    if value.is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    }
}

/// Now, as RFC 5424 writes it: `2026-09-08T10:30:00.123456Z`.
#[must_use]
pub fn timestamp_now() -> String {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let (date, time) = civil(since.as_secs());
    format!("{date}T{time}.{:06}Z", since.subsec_micros())
}

/// Seconds since the epoch to `YYYY-MM-DD` and `HH:MM:SS`, proleptic
/// Gregorian, Howard Hinnant's algorithm.
fn civil(seconds: u64) -> (String, String) {
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rem = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!("{:02}:{:02}:{:02}", rem / 3600, (rem % 3600) / 60, rem % 60),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_round_trips_through_its_header() {
        let header = Header {
            facility: 20,
            severity: 5,
            timestamp: "2026-09-08T10:30:00Z".into(),
            hostname: "edge-01".into(),
            app_name: "xmip".into(),
            proc_id: "-".into(),
            msg_id: "ORDER".into(),
            structured_data: r#"[x@1 a="b\]c" d="e"][y@2]"#.into(),
        };
        let bytes = format(&header, b"ping\r\npong");
        assert!(bytes.starts_with(b"<165>1 2026-09-08T10:30:00Z edge-01 xmip - ORDER [x@1"));
        let (back, msg) = parse(&bytes).expect("parse");
        assert_eq!(back, header);
        assert_eq!(msg, b"ping\r\npong");
        let bare = format(&header, b"");
        let (_, empty) = parse(&bare).expect("no msg");
        assert!(empty.is_empty());
    }

    #[test]
    fn what_is_not_rfc_5424_is_refused() {
        assert!(parse(b"hello").is_err(), "no PRI");
        assert!(parse(b"<1234>1 - - - - - -").is_err(), "four digits");
        assert!(parse(b"<200>1 - - - - - -").is_err(), "over 191");
        assert!(parse(b"<34>0 - - - - - -").is_err(), "version 0");
        assert!(parse(b"<34>1 - - -").is_err(), "short");
        assert!(parse(b"<34>1 - - - - - [a").is_err(), "unclosed");
        assert!(parse(b"<34>1 - - - - - x").is_err(), "bad SD");
        assert!(parse(b"<34>1 - - - - - -x").is_err(), "no space");
        let (header, msg) = parse(b"<34>1 - - - - - - ").expect("empty msg");
        assert_eq!((header.facility, header.severity), (4, 2));
        assert!(msg.is_empty());
    }

    #[test]
    fn the_timestamp_is_utc_iso_8601() {
        let (date, time) = civil(1_788_000_000);
        assert_eq!(date, "2026-08-29");
        assert_eq!(time, "10:40:00");
        assert_eq!(civil(0), ("1970-01-01".to_string(), "00:00:00".to_string()));
        assert!(timestamp_now().ends_with('Z'));
        assert_eq!(Header::now(1, 6, "", "").hostname, "-");
    }
}
