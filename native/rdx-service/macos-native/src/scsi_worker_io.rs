// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deadline-bound parent pipe I/O; no operation in this module opens a device.

use crate::NativeError;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::time::Instant;

/// Makes only an owned parent pipe nonblocking, preserving its other descriptor flags.
pub(super) fn nonblocking(pipe: &impl AsRawFd) -> Result<(), NativeError> {
    let fd = pipe.as_raw_fd();
    // SAFETY: the borrowed owner keeps this descriptor live for both fcntl calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(NativeError::TransportUnavailable);
    }
    Ok(())
}

/// Waits for one nonblocking pipe until a shared absolute monotonic deadline.
fn ready(pipe: &impl AsRawFd, events: i16, deadline: Instant) -> Result<(), NativeError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(NativeError::TimedOut)?;
        let milliseconds = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: poll receives one initialized record and never takes descriptor ownership.
        let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if result == 0 {
            return Err(NativeError::TimedOut);
        }
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(NativeError::TransportUnavailable);
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(NativeError::TransportUnavailable);
        }
        // HUP still permits buffered input to be consumed; the next read reports EOF.
        if descriptor.revents & (events | libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(());
        }
    }
}

/// Reads an exact bounded frame fragment; partial progress never extends its deadline.
pub(super) fn read_exact(
    pipe: &mut (impl Read + AsRawFd),
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), NativeError> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(NativeError::TimedOut);
        }
        match pipe.read(bytes) {
            Ok(0) => return Err(NativeError::TransportUnavailable),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                ready(pipe, libc::POLLIN, deadline)?
            }
            Err(_) => return Err(NativeError::TransportUnavailable),
        }
    }
    Ok(())
}

/// Writes one complete frame; failure retains the exact known prefix count.
pub(super) fn write_all(
    pipe: &mut (impl Write + AsRawFd),
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), (NativeError, usize)> {
    let mut written = 0;
    while written < bytes.len() {
        if Instant::now() >= deadline {
            return Err((NativeError::TimedOut, written));
        }
        match pipe.write(&bytes[written..]) {
            Ok(0) => return Err((NativeError::TransportUnavailable, written)),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                ready(pipe, libc::POLLOUT, deadline).map_err(|error| (error, written))?;
            }
            Err(_) => return Err((NativeError::TransportUnavailable, written)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// A silent initialized peer cannot keep parent reads blocked past their deadline.
    #[test]
    fn silent_peer_and_partial_frame_read_are_bounded() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        nonblocking(&reader).unwrap();
        writer.write_all(&[1]).unwrap();
        let mut bytes = [0; 2];
        assert_eq!(
            read_exact(
                &mut reader,
                &mut bytes,
                Instant::now() + Duration::from_millis(20)
            ),
            Err(NativeError::TimedOut)
        );
        assert_eq!(bytes[0], 1);
    }

    /// A nonreading child cannot block a parent write, and prefix accounting stays exact.
    #[test]
    fn saturated_pipe_write_is_bounded_and_retains_prefix_count() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        nonblocking(&writer).unwrap();
        nonblocking(&reader).unwrap();
        let payload = vec![0x5a; 8 * 1024 * 1024];
        let (error, written) = write_all(
            &mut writer,
            &payload,
            Instant::now() + Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(error, NativeError::TimedOut);
        assert!(written > 0 && written < payload.len());
        let mut received = Vec::new();
        let _ = reader.read_to_end(&mut received);
        assert_eq!(received.len(), written);
        assert!(received.iter().all(|byte| *byte == 0x5a));
    }

    /// An expired deadline performs no read/write even when bytes or capacity are available.
    #[test]
    fn expired_deadlines_do_not_dispatch_bytes() {
        let (mut left, mut right) = UnixStream::pair().unwrap();
        nonblocking(&left).unwrap();
        right.write_all(&[1]).unwrap();
        let deadline = Instant::now();
        assert_eq!(
            write_all(&mut left, &[2], deadline),
            Err((NativeError::TimedOut, 0))
        );
        assert_eq!(
            read_exact(&mut left, &mut [0], deadline),
            Err(NativeError::TimedOut)
        );
    }
}
