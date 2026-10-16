// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Readiness publication after authenticated Windows backend preparation.

use rdx_service::endpoint::HandshakeDeadlineReader;
use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

/// Prepares the backend before arming the unchanged two-second frame deadline.
///
/// The caller already owns the authenticated pipe and hardware ownership guard.
/// No readiness bytes are written after an observed stop. Transport errors are
/// propagated without accepting a partial marker or consuming any client frame.
pub(super) fn prepare_session<B, R, W, F, S, N, P>(
    prepare: P,
    reader: R,
    mut writer: W,
    set_timeout: F,
    stop: S,
    now: N,
) -> io::Result<(B, HandshakeDeadlineReader<R, F, N>, W)>
where
    R: Read,
    W: Write,
    F: FnMut(&mut R, Option<Duration>) -> io::Result<()>,
    S: Fn() -> bool,
    N: Fn() -> Instant,
    P: FnOnce() -> B,
{
    let backend = prepare();
    if stop() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    let reader =
        HandshakeDeadlineReader::with_clock(reader, super::FIRST_FRAME_TIMEOUT, set_timeout, now)?;
    if stop() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    writer.write_all(b"OpenRDX:ready:1\n")?;
    Ok((backend, reader, writer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        io::{self, Cursor, Read},
        rc::Rc,
        time::Instant,
    };

    /// Backend work must not consume the first queued frame's absolute budget.
    #[test]
    fn queued_frame_survives_slow_backend_preparation() {
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let base = Instant::now();
        let prepared = Cell::new(false);
        let (backend, mut reader, output) = prepare_session(
            || {
                elapsed.set(Duration::from_secs(3));
                prepared.set(true);
                42
            },
            Cursor::new(vec![0, 0, 0, 1, b'x']),
            Vec::new(),
            |_, timeout| {
                assert!(prepared.get());
                assert!(timeout.is_none_or(|value| value <= Duration::from_secs(2)));
                Ok(())
            },
            || false,
            || base + elapsed.get(),
        )
        .unwrap();
        assert_eq!(backend, 42);
        assert_eq!(output, b"OpenRDX:ready:1\n");
        let mut frame = Vec::new();
        reader.read_to_end(&mut frame).unwrap();
        assert_eq!(frame, vec![0, 0, 0, 1, b'x']);
    }

    /// Neither idle input nor a partial prefix may restart the frame deadline.
    #[test]
    fn idle_and_partial_frames_expire_at_the_original_deadline() {
        for prefix in [false, true] {
            let elapsed = Cell::new(Duration::ZERO);
            let base = Instant::now();
            let (_, mut reader, _) = prepare_session(
                || (),
                Cursor::new(vec![0, 0, 0, 1, b'x']),
                Vec::new(),
                |_, _| Ok(()),
                || false,
                || base + elapsed.get(),
            )
            .unwrap();
            if prefix {
                elapsed.set(Duration::from_secs(1));
                reader.read_exact(&mut [0; 4]).unwrap();
            }
            elapsed.set(Duration::from_secs(2));
            assert_eq!(
                reader.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }

    /// A STOP before publication must never emit even a partial ready marker.
    #[test]
    fn observed_stop_before_publication_emits_nothing() {
        for stop_during_arm in [false, true] {
            let stopped = Cell::new(!stop_during_arm);
            let mut output = Vec::new();
            let result = prepare_session(
                || (),
                Cursor::new(vec![0, 0, 0, 1, b'x']),
                &mut output,
                |_, _| {
                    stopped.set(true);
                    Ok(())
                },
                || stopped.get(),
                Instant::now,
            );
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
            assert!(output.is_empty());
        }
    }
}
