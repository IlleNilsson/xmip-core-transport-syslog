//! One TCP sender's connection, kept open at a Receive Location between
//! its messages.
//!
//! A sender keeps its connection between messages (`transport::Pool`), so a
//! receive that read one connection until its sender closed would hold
//! that receive for good. Each framed message is one turn instead
//! (`transport::serving::Turn`), taken from whichever sender sends first,
//! and the connection is kept beside the listener for the next
//! (`transport::serving::Serving`). Nothing is answered: acceptance is
//! at-most-once ([`crate::AT_MOST_ONCE`]). Until 2026-10-21 a receive read
//! one connection until its sender closed, and every send opened one.

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream};

use net::ceiling;
use net::{MAX_BODY, read};
use transport::Arrived;
use transport::error::{Result, classify, protocol_error};
use transport::serving::{Open, Turn};

/// One TCP sender's messages, octet-counted or newline-terminated, RFC 6587.
pub struct Connection {
    reader: BufReader<TcpStream>,
    peer: SocketAddr,
}

impl Connection {
    /// A sender's connection from `peer`.
    #[must_use]
    pub fn new(stream: TcpStream, peer: SocketAddr) -> Self {
        Self {
            reader: BufReader::new(stream),
            peer,
        }
    }

    /// The next message, or `None` when the sender closed between messages.
    ///
    /// # Errors
    /// A frame that breaks off, a count or a line over `net::MAX_BODY`, or a
    /// message that is not RFC 5424.
    pub fn next_message(&mut self) -> Result<Option<Arrived>> {
        let first = match self.reader.fill_buf() {
            Ok([]) => return Ok(None),
            Ok(buffer) => buffer[0],
            Err(error) => return Err(classify("reading a frame", &error)),
        };
        let raw = if first.is_ascii_digit() {
            // The count and its space: no count Xmip reads has more digits
            // than the ceiling itself.
            let digits = usize::try_from(MAX_BODY.ilog10()).unwrap_or(usize::MAX) + 2;
            let mut count = Vec::new();
            read::until(&mut self.reader, b' ', digits, &mut count)?;
            let count: usize = std::str::from_utf8(&count)
                .ok()
                .and_then(|c| c.trim().parse().ok())
                .ok_or_else(|| protocol_error("an octet count that is not a number"))?;
            ceiling::within(count, MAX_BODY, "Xmip reads in one frame")?;
            let mut raw = vec![0u8; count];
            self.reader
                .read_exact(&mut raw)
                .map_err(|e| classify("reading the message", &e))?;
            raw
        } else {
            let mut raw = Vec::new();
            read::until(&mut self.reader, b'\n', MAX_BODY, &mut raw)?;
            while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                raw.pop();
            }
            raw
        };
        crate::arrived(self.peer, &raw).map(Some)
    }

    /// One turn for a kept listener: the next message, or the sender gone.
    ///
    /// # Errors
    /// As [`Connection::next_message`].
    pub fn turn(&mut self) -> Result<Turn<Arrived>> {
        Ok(self.next_message()?.map_or(Turn::Closed, Turn::Taken))
    }
}

impl Open for Connection {
    fn socket(&self) -> &TcpStream {
        self.reader.get_ref()
    }

    /// A message the last read took beside its own waits in the reader.
    fn waiting(&self) -> bool {
        !self.reader.buffer().is_empty()
    }
}
