// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generation-scoped authority for non-cloneable native macOS candidates.

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
    /// Returns the bounded count of previously committed rematch recipes.
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

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
        let locator = OsString::from(format!("mac:{:016X}:{token}", self.generation));
        if self.entries.contains_key(&locator) {
            return Err(PlatformError::DuplicateCandidate);
        }
        self.entries.insert(locator.clone(), value);
        Ok(locator)
    }

    /// Reopens one staged recipe for validation without publishing it.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn reopen(&self, locator: &OsStr) -> Option<&T> {
        self.entries.get(locator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Discovery validation and later resolutions reopen the same private recipe.
    #[test]
    fn discovery_recipe_can_be_reopened_repeatedly() {
        let mut pending = PendingCandidateAuthority::default();
        let mut staged = pending.stage_generation().expect("first generation");
        let locator = staged
            .retain("macos-candidate-000", 7)
            .expect("retain recipe");
        pending.commit_generation(staged);

        assert_eq!(pending.reopen(&locator), Some(&7));
        assert_eq!(pending.reopen(&locator), Some(&7));
    }

    /// An incomplete refresh never destroys the last complete recipe generation.
    #[test]
    fn failed_refresh_preserves_previous_generation() {
        let mut pending = PendingCandidateAuthority::default();
        let mut first = pending.stage_generation().expect("first generation");
        let locator = first
            .retain("macos-candidate-000", 7)
            .expect("retain recipe");
        pending.commit_generation(first);

        let mut failed = pending.stage_generation().expect("staged refresh");
        failed
            .retain("macos-candidate-000", 9)
            .expect("staged replacement");
        drop(failed);

        assert_eq!(pending.reopen(&locator), Some(&7));
    }

    /// Committed recipe presence controls only the bounded rematch grace path.
    #[test]
    fn committed_authority_reports_the_expected_rematch_count() {
        let mut pending = PendingCandidateAuthority::default();
        assert_eq!(pending.len(), 0);
        let mut staged = pending.stage_generation().expect("first generation");
        staged.retain("macos-candidate-000", 7).unwrap();
        pending.commit_generation(staged);
        assert_eq!(pending.len(), 1);
    }

    /// A committed hotplug generation invalidates old locators even after ID reuse.
    #[test]
    fn committed_refresh_rejects_hotplugged_registry_id_reuse() {
        let mut pending = PendingCandidateAuthority::default();
        let mut first = pending.stage_generation().expect("first generation");
        let stale = first
            .retain("macos-candidate-000", 7)
            .expect("retain first recipe");
        pending.commit_generation(first);

        let mut replacement = pending.stage_generation().expect("replacement generation");
        let current = replacement
            .retain("macos-candidate-000", 9)
            .expect("retain replacement recipe");
        pending.commit_generation(replacement);

        assert_eq!(pending.reopen(&stale), None);
        assert_eq!(pending.reopen(&current), Some(&9));
    }
}
