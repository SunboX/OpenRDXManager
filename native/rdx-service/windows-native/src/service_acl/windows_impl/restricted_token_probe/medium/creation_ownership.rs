// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Successful creation owns cleanup before any later identifier sanity rejection.

/// Keeps an already-owned creation only when its returned PID is nonzero and distinct.
/// Rejection drops the guard; callers supply only trusted API-created owned handles.
pub fn retain_valid_creation<T>(owned: T, process: u32, source: u32) -> Option<T> {
    if process == 0 || process == source {
        None
    } else {
        Some(owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Models cleanup ownership without any process/PID operation on the host.
    struct Guard<'a>(&'a Cell<u32>);
    impl Drop for Guard<'_> {
        /// Records exactly one owned cleanup when this synthetic guard is rejected/dropped.
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// Post-create rejection cannot discard cleanup ownership before dropping the guard.
    #[test]
    fn rejected_creation_drops_owned_guard() {
        for process in [0, 7] {
            let cleaned = Cell::new(0);
            assert!(retain_valid_creation(Guard(&cleaned), process, 7).is_none());
            assert!(cleaned.get() == 1);
        }
    }

    /// Admitted creation retains its guard until the owner explicitly drops it.
    #[test]
    fn valid_creation_retains_owned_guard() {
        let cleaned = Cell::new(0);
        let owned = retain_valid_creation(Guard(&cleaned), 8, 7);
        assert!(owned.is_some());
        assert!(cleaned.get() == 0);
        drop(owned);
        assert!(cleaned.get() == 1);
    }
}
