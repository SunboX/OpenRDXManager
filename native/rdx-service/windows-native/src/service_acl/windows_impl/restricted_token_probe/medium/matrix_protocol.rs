// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed test roles and bounded execution budget, with no arbitrary object/mask/trustee interface.

/// Eight independently owned compiled controls; bits never arrive from CLI or environment.
#[derive(Clone, Copy)]
pub(super) enum Row {
    Baseline,
    Process,
    Thread,
    ProcessThread,
    Token,
    ProcessToken,
    ThreadToken,
    All,
}
impl Row {
    pub(super) const ALL: [Self; 8] = [
        Self::Baseline,
        Self::Process,
        Self::Thread,
        Self::ProcessThread,
        Self::Token,
        Self::ProcessToken,
        Self::ThreadToken,
        Self::All,
    ];
    /// Closed public tag, never a user-provided string.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::ProcessThread => "process-thread",
            Self::Token => "token",
            Self::ProcessToken => "process-token",
            Self::ThreadToken => "thread-token",
            Self::All => "process-thread-token",
        }
    }
    /// Exact roles selected by the finite matrix.
    pub(super) fn objects(self) -> [bool; 3] {
        match self {
            Self::Baseline => [false, false, false],
            Self::Process => [true, false, false],
            Self::Thread => [false, true, false],
            Self::ProcessThread => [true, true, false],
            Self::Token => [false, false, true],
            Self::ProcessToken => [true, false, true],
            Self::ThreadToken => [false, true, true],
            Self::All => [true, true, true],
        }
    }
}

/// Reserves the 10-second wait and three bounded 3-second owned-handle cleanup attempts.
pub(super) fn launch_budget(remaining_ms: u128) -> bool {
    remaining_ms >= 19_000
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Finite roles are unique and exhaust only the eight approved object combinations.
    #[test]
    fn fixed_roles_are_exact() {
        let mut names = std::collections::HashSet::new();
        let mut objects = std::collections::HashSet::new();
        for row in Row::ALL {
            assert!(names.insert(row.name()));
            assert!(objects.insert(row.objects()));
        }
        assert!(names.len() == 8 && objects.len() == 8);
    }
    /// An insufficient global reserve forbids another creation instead of abandoning a child.
    #[test]
    fn creation_requires_reaping_reserve() {
        for remaining in [0, 100, 2_999, 3_000, 13_000, 18_999] {
            assert!(!launch_budget(remaining));
        }
        for remaining in [19_000, 90_000] {
            assert!(launch_budget(remaining));
        }
    }
}
