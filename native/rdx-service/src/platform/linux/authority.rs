// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generation-scoped authority for non-cloneable native Linux candidates.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use super::super::{MAX_CANDIDATE_DEVICES, PlatformError};

/// Bounded reusable candidate recipes from the last complete enumeration pass.
pub(super) struct PendingCandidateAuthority<T> {
    generation: u64,
    entries: BTreeMap<OsString, T>,
}

/// Complete replacement generation kept private until every candidate is valid.
pub(super) struct StagedCandidateAuthority<T> {
    generation: u64,
    entries: BTreeMap<OsString, T>,
}

impl<T> Default for PendingCandidateAuthority<T> {
    /// Starts without issued authority.
    fn default() -> Self {
        Self {
            generation: 0,
            entries: BTreeMap::new(),
        }
    }
}

impl<T> PendingCandidateAuthority<T> {
    /// Starts a fallible replacement without changing current reopen authority.
    pub(super) fn stage_generation(&self) -> Result<StagedCandidateAuthority<T>, PlatformError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(PlatformError::TooManyCandidates)?;
        Ok(StagedCandidateAuthority {
            generation,
            entries: BTreeMap::new(),
        })
    }

    /// Atomically publishes one complete staged generation.
    pub(super) fn commit_generation(&mut self, staged: StagedCandidateAuthority<T>) {
        self.generation = staged.generation;
        self.entries = staged.entries;
    }

    /// Reopens one exact recipe without consuming future resolution authority.
    pub(super) fn reopen(&self, locator: &OsStr) -> Option<&T> {
        self.entries.get(locator)
    }
}

impl<T> StagedCandidateAuthority<T> {
    /// Retains one native recipe under a path-free staged-generation locator.
    pub(super) fn retain(&mut self, token: &str, value: T) -> Result<OsString, PlatformError> {
        if self.entries.len() == MAX_CANDIDATE_DEVICES {
            return Err(PlatformError::TooManyCandidates);
        }
        let locator = OsString::from(format!("lnx:{:016X}:{token}", self.generation));
        if self.entries.contains_key(&locator) {
            return Err(PlatformError::DuplicateCandidate);
        }
        self.entries.insert(locator.clone(), value);
        Ok(locator)
    }

    /// Reopens one staged recipe for validation without publishing it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn reopen(&self, locator: &OsStr) -> Option<&T> {
        self.entries.get(locator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Discovery validation and later resolutions reopen the same private recipe.
    #[test]
    fn discovery_validation_preserves_operation_resolution_authority() {
        let mut pending = PendingCandidateAuthority::default();
        let mut staged = pending.stage_generation().expect("first generation");
        let locator = staged.retain("linux-sg-2", 7).expect("retain recipe");
        pending.commit_generation(staged);

        assert_eq!(pending.reopen(&locator), Some(&7));
        assert_eq!(pending.reopen(&locator), Some(&7));
    }

    /// An incomplete refresh never destroys the last complete recipe generation.
    #[test]
    fn failed_refresh_preserves_previous_generation() {
        let mut pending = PendingCandidateAuthority::default();
        let mut first = pending.stage_generation().expect("first generation");
        let locator = first.retain("linux-sg-2", 7).expect("retain recipe");
        pending.commit_generation(first);

        let mut failed = pending.stage_generation().expect("staged refresh");
        failed.retain("linux-sg-2", 9).expect("staged replacement");
        drop(failed);

        assert_eq!(pending.reopen(&locator), Some(&7));
    }

    /// The bounded store rejects duplicates without replacing retained authority.
    #[test]
    fn staged_authority_is_bounded_and_duplicate_safe() {
        let pending = PendingCandidateAuthority::default();
        let mut staged = pending.stage_generation().expect("generation");
        let first = staged.retain("linux-sg-0", 0).expect("first");
        assert_eq!(
            staged.retain("linux-sg-0", 999),
            Err(PlatformError::DuplicateCandidate)
        );
        for index in 1..MAX_CANDIDATE_DEVICES {
            staged
                .retain(&format!("linux-sg-{index}"), index)
                .expect("bounded recipe");
        }
        assert_eq!(
            staged.retain("overflow", MAX_CANDIDATE_DEVICES),
            Err(PlatformError::TooManyCandidates)
        );
        assert_eq!(staged.reopen(&first), Some(&0));
    }

    /// A committed hotplug generation invalidates old locators even after ID reuse.
    #[test]
    fn committed_refresh_rejects_hotplugged_registry_id_reuse() {
        let mut pending = PendingCandidateAuthority::default();
        let mut first = pending.stage_generation().expect("first generation");
        let stale = first.retain("linux-sg-2", 7).expect("retain first recipe");
        pending.commit_generation(first);

        let mut replacement = pending.stage_generation().expect("replacement generation");
        let current = replacement
            .retain("linux-sg-2", 9)
            .expect("retain replacement recipe");
        pending.commit_generation(replacement);

        assert_eq!(pending.reopen(&stale), None);
        assert_eq!(pending.reopen(&current), Some(&9));
    }
}
