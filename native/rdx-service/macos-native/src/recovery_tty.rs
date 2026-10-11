// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed terminal-input freshness boundary; no USB or device operations.

use crate::NativeError;

/// Discards queued stdin input immediately before arming an operator prompt.
///
/// Requires an actual terminal and uses Darwin TCIFLUSH on stdin only. Failure
/// must prevent prompt acceptance. This neither reads a reply nor proves that
/// an operator performed the requested physical action.
pub fn discard_recovery_terminal_input() -> Result<(), NativeError> {
    #[cfg(target_os = "macos")]
    {
        use std::io::IsTerminal;
        flush_terminal(std::io::stdin().is_terminal(), || {
            // SAFETY: Darwin sys/termios.h defines TCIFLUSH=1. fd0 is borrowed;
            // tcflush discards pending input and never closes the descriptor.
            unsafe { tcflush(0, 1) }
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Requires terminal evidence before invoking the fixed flush, with no retry.
#[cfg(any(target_os = "macos", test))]
fn flush_terminal(terminal: bool, flush: impl FnOnce() -> i32) -> Result<(), NativeError> {
    if !terminal || flush() != 0 {
        Err(NativeError::InvalidRequest)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn tcflush(descriptor: i32, queue_selector: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pipes never reach the native flush and errors never turn into acknowledgment.
    #[test]
    fn terminal_and_flush_success_are_both_required() {
        assert!(flush_terminal(false, || panic!("must not flush")).is_err());
        assert!(flush_terminal(true, || -1).is_err());
        assert_eq!(flush_terminal(true, || 0), Ok(()));
    }
}
