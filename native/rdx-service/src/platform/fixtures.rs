// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic path-free host-operation fixtures for service state-machine tests.

use std::collections::BTreeSet;

use crate::model::ConfirmationToken;
use crate::operations::{
    FileSystem, HostOperations, HostPrimitiveError, HostVolumeBinding, HostVolumeFacts,
    PrimitiveFailure, VolumeTopology, WriteReadPrimitiveResult,
};

/// Fixture-friendly topology choices with no device paths or handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureTopology {
    /// One exact simple physical disk.
    Simple,
    /// Host boot/system/root storage is involved.
    BootOrSystem,
    /// A layered mapping is involved.
    Layered,
    /// A shared physical mapping is involved.
    Shared,
    /// A spanned or multipath mapping is involved.
    Spanned,
    /// Complete topology is unavailable.
    Ambiguous,
}

impl From<FixtureTopology> for VolumeTopology {
    /// Converts deterministic fixture topology into production classification.
    fn from(value: FixtureTopology) -> Self {
        match value {
            FixtureTopology::Simple => Self::Simple,
            FixtureTopology::BootOrSystem => Self::BootOrSystem,
            FixtureTopology::Layered => Self::Layered,
            FixtureTopology::Shared => Self::Shared,
            FixtureTopology::Spanned => Self::Spanned,
            FixtureTopology::Ambiguous => Self::Ambiguous,
        }
    }
}

/// Deterministic host adapter that records closed semantic actions only.
pub struct FixtureHost {
    binding: HostVolumeBinding,
    facts: HostVolumeFacts,
    media_swap_at_revalidation: Option<usize>,
    revalidation_count: usize,
    missing_dependency: Option<FileSystem>,
    unmount_rejection: bool,
    layout_completion_unknown: bool,
    format_not_attempted_after_layout: bool,
    eject_completion_unknown: bool,
    eject_departure_unconfirmed: bool,
    format_postcondition_unconfirmed: bool,
    cleanup_completion_unknown: bool,
    readback_corruption: bool,
    letter_collisions: BTreeSet<char>,
    current_drive_letter: Option<char>,
    mapping_app_owned: bool,
    unmount_count: usize,
    safe_eject_count: usize,
    force_eject_count: usize,
    layout_change_count: usize,
    format_count: usize,
    set_volume_label_count: usize,
    current_volume_label: Option<String>,
    set_drive_letter_count: usize,
    reset_drive_letter_count: usize,
    flush_count: usize,
    reopen_count: usize,
    delete_count: usize,
    last_filename: Option<String>,
    exclusive_no_follow: Option<bool>,
    last_mbr_signature: Option<u32>,
    session_invalidated: bool,
}

impl FixtureHost {
    /// Creates inserted, mounted, writable, simple disposable media.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            binding: HostVolumeBinding::new(7, [0x5A; 32], Some([0xC3; 32])),
            facts: HostVolumeFacts {
                media_present: true,
                writable: true,
                mounted: true,
                free_bytes: 128 * 1024 * 1024,
                capacity_bytes: 500 * 1024 * 1024,
                filesystem: Some(FileSystem::ExFat),
                topology: VolumeTopology::Simple,
                media_fingerprint: Some([0xC3; 32]),
            },
            media_swap_at_revalidation: None,
            revalidation_count: 0,
            missing_dependency: None,
            unmount_rejection: false,
            layout_completion_unknown: false,
            format_not_attempted_after_layout: false,
            eject_completion_unknown: false,
            eject_departure_unconfirmed: false,
            format_postcondition_unconfirmed: false,
            cleanup_completion_unknown: false,
            readback_corruption: false,
            letter_collisions: BTreeSet::new(),
            current_drive_letter: None,
            mapping_app_owned: false,
            unmount_count: 0,
            safe_eject_count: 0,
            force_eject_count: 0,
            layout_change_count: 0,
            format_count: 0,
            set_volume_label_count: 0,
            current_volume_label: None,
            set_drive_letter_count: 0,
            reset_drive_letter_count: 0,
            flush_count: 0,
            reopen_count: 0,
            delete_count: 0,
            last_filename: None,
            exclusive_no_follow: None,
            last_mbr_signature: None,
            session_invalidated: false,
        }
    }

    /// Makes the mounted cartridge read-only for mutation preflight tests.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.facts.writable = false;
        self
    }

    /// Reports the label accepted by the exact-volume fixture primitive.
    #[must_use]
    pub fn current_volume_label(&self) -> Option<&str> {
        self.current_volume_label.as_deref()
    }

    /// Counts only actual label primitives after binding revalidation.
    #[must_use]
    pub const fn set_volume_label_count(&self) -> usize {
        self.set_volume_label_count
    }

    /// Removes media for drive-letter configuration fixtures.
    #[must_use]
    pub fn without_media(mut self) -> Self {
        self.facts.media_present = false;
        self.facts.mounted = false;
        self.facts.free_bytes = 0;
        self.facts.media_fingerprint = None;
        self.binding = HostVolumeBinding::new(7, [0x5A; 32], None);
        self
    }

    /// Makes exact unmount definitely reject as busy.
    #[must_use]
    pub fn with_unmount_rejection(mut self) -> Self {
        self.unmount_rejection = true;
        self
    }

    /// Makes one requested format dependency unavailable.
    #[must_use]
    pub fn with_missing_dependency(mut self, filesystem: FileSystem) -> Self {
        self.missing_dependency = Some(filesystem);
        self
    }

    /// Replaces the complete topology classification.
    #[must_use]
    pub fn with_topology(mut self, topology: FixtureTopology) -> Self {
        self.facts.topology = topology.into();
        self
    }

    /// Makes layout dispatch begin without provable completion.
    #[must_use]
    pub fn with_layout_completion_unknown(mut self) -> Self {
        self.layout_completion_unknown = true;
        self
    }

    /// Swaps to a different same-capacity cartridge at one fresh boundary.
    #[must_use]
    pub fn with_media_swap_at_revalidation(mut self, boundary: usize) -> Self {
        self.media_swap_at_revalidation = Some(boundary);
        self
    }

    /// Makes the formatter reject after layout has already succeeded.
    #[must_use]
    pub fn with_format_not_attempted_after_layout(mut self) -> Self {
        self.format_not_attempted_after_layout = true;
        self
    }

    /// Makes native eject dispatch complete with an ambiguous callback result.
    #[must_use]
    pub fn with_eject_completion_unknown(mut self) -> Self {
        self.eject_completion_unknown = true;
        self
    }

    /// Makes post-eject exact departure impossible to prove.
    #[must_use]
    pub fn with_eject_departure_unconfirmed(mut self) -> Self {
        self.eject_departure_unconfirmed = true;
        self
    }

    /// Makes post-format authoritative rediscovery impossible to prove.
    #[must_use]
    pub fn with_format_postcondition_unconfirmed(mut self) -> Self {
        self.format_postcondition_unconfirmed = true;
        self
    }

    /// Issues the same bounded binding token as the production matcher.
    #[must_use]
    pub fn issue_confirmation_token(&self) -> ConfirmationToken {
        self.binding.issue_confirmation_token()
    }

    /// Makes exact temporary-file deletion completion unknown.
    #[must_use]
    pub fn with_cleanup_completion_unknown(mut self) -> Self {
        self.cleanup_completion_unknown = true;
        self
    }

    /// Corrupts one readback byte after a successful reopen.
    #[must_use]
    pub fn with_readback_corruption(mut self) -> Self {
        self.readback_corruption = true;
        self
    }

    /// Marks one drive letter as owned by another volume.
    #[must_use]
    pub fn with_letter_collision(mut self, letter: char) -> Self {
        self.letter_collisions.insert(letter);
        self
    }

    /// Installs a foreign mapping which reset must never delete.
    #[must_use]
    pub fn with_foreign_mapping(mut self, letter: char) -> Self {
        self.current_drive_letter = Some(letter);
        self.mapping_app_owned = false;
        self
    }

    /// Returns exact unmount primitive invocation count.
    #[must_use]
    pub const fn unmount_count(&self) -> usize {
        self.unmount_count
    }

    /// Returns normal eject primitive invocation count.
    #[must_use]
    pub const fn safe_eject_count(&self) -> usize {
        self.safe_eject_count
    }

    /// Returns forced eject primitive invocation count.
    #[must_use]
    pub const fn force_eject_count(&self) -> usize {
        self.force_eject_count
    }

    /// Returns partition-layout primitive invocation count.
    #[must_use]
    pub const fn layout_change_count(&self) -> usize {
        self.layout_change_count
    }

    /// Returns filesystem-format primitive invocation count.
    #[must_use]
    pub const fn format_count(&self) -> usize {
        self.format_count
    }

    /// Returns drive-letter set primitive invocation count.
    #[must_use]
    pub const fn set_drive_letter_count(&self) -> usize {
        self.set_drive_letter_count
    }

    /// Returns drive-letter reset primitive invocation count.
    #[must_use]
    pub const fn reset_drive_letter_count(&self) -> usize {
        self.reset_drive_letter_count
    }

    /// Returns write-buffer flush invocation count.
    #[must_use]
    pub const fn flush_count(&self) -> usize {
        self.flush_count
    }

    /// Returns exact-file reopen invocation count.
    #[must_use]
    pub const fn reopen_count(&self) -> usize {
        self.reopen_count
    }

    /// Returns exact-file delete invocation count.
    #[must_use]
    pub const fn delete_count(&self) -> usize {
        self.delete_count
    }

    /// Returns the last app-owned basename without any directory.
    #[must_use]
    pub fn last_test_filename(&self) -> Option<&str> {
        self.last_filename.as_deref()
    }

    /// Returns whether create-new and no-follow semantics were requested together.
    #[must_use]
    pub const fn created_with_exclusive_no_follow(&self) -> Option<bool> {
        self.exclusive_no_follow
    }

    /// Returns the latest layout signature supplied to the fixture.
    #[must_use]
    pub const fn last_mbr_signature(&self) -> Option<u32> {
        self.last_mbr_signature
    }

    /// Reports whether the service session was invalidated for rediscovery.
    #[must_use]
    pub const fn session_invalidated(&self) -> bool {
        self.session_invalidated
    }

    /// Returns the currently stored drive-letter preference.
    #[must_use]
    pub const fn current_drive_letter(&self) -> Option<char> {
        self.current_drive_letter
    }

    /// Reports whether the current mapping was written by this exact fixture binding.
    #[must_use]
    pub const fn mapping_is_app_owned(&self) -> bool {
        self.mapping_app_owned
    }

    /// Revalidates one fixture boundary and optionally performs an adversarial swap.
    fn revalidate_boundary(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.revalidation_count += 1;
        if self.media_swap_at_revalidation == Some(self.revalidation_count) {
            self.facts.media_fingerprint = Some([0xD4; 32]);
            self.binding = HostVolumeBinding::new(7, [0x5A; 32], Some([0xD4; 32]));
        }
        if *expected != self.binding || expected.media_fingerprint() != self.facts.media_fingerprint
        {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        Ok(self.facts)
    }
}

impl HostOperations for FixtureHost {
    /// Revalidates again at the mutation boundary, including adversarial swaps.
    fn set_volume_label_exact(
        &mut self,
        expected: &HostVolumeBinding,
        label: &crate::model::VolumeLabel,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        self.set_volume_label_count += 1;
        self.current_volume_label = Some(label.as_str().to_owned());
        Ok(())
    }

    /// Captures the fixed path-free fixture binding.
    fn binding(&self) -> HostVolumeBinding {
        self.binding.clone()
    }

    /// Revalidates exact equality and returns current fixture facts.
    fn revalidate(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.revalidate_boundary(expected)
    }

    /// Rejects the configured missing dependency without mutation.
    fn preflight_format(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        if self.missing_dependency == Some(filesystem) {
            Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::DependencyMissing,
            ))
        } else {
            Ok(())
        }
    }

    /// Records closed exact-file semantics and returns deterministic bytes.
    fn write_read_file(
        &mut self,
        expected: &HostVolumeBinding,
        filename: &str,
        bytes: &[u8],
    ) -> Result<WriteReadPrimitiveResult, PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        if !filename.starts_with(".openrdx-write-read-")
            || !filename.ends_with(".tmp")
            || filename.contains('/')
            || filename.contains('\\')
            || bytes.is_empty()
        {
            return Err(PrimitiveFailure::not_attempted(HostPrimitiveError::Other));
        }
        self.last_filename = Some(filename.to_owned());
        self.exclusive_no_follow = Some(true);
        self.flush_count += 1;
        self.reopen_count += 1;
        self.delete_count += 1;
        let mut readback = bytes.to_vec();
        if self.readback_corruption {
            readback[0] ^= 0xFF;
        }
        let cleanup = if self.cleanup_completion_unknown {
            Err(PrimitiveFailure::completion_unknown(
                HostPrimitiveError::Other,
            ))
        } else {
            Ok(())
        };
        Ok(WriteReadPrimitiveResult {
            operation: Ok(readback),
            cleanup,
        })
    }

    /// Records exact safe unmount or rejects as busy before changing state.
    fn unmount_exact_volumes(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        self.unmount_count += 1;
        if self.unmount_rejection {
            Err(PrimitiveFailure::definitely_rejected(
                HostPrimitiveError::Busy,
            ))
        } else {
            self.facts.mounted = false;
            Ok(())
        }
    }

    /// Runs safe unmount and only then the normal eject primitive.
    fn safe_eject_exact(
        &mut self,
        expected: &HostVolumeBinding,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), PrimitiveFailure> {
        self.unmount_exact_volumes(expected)?;
        if !after_unmount() {
            return Err(PrimitiveFailure::completion_unknown(
                HostPrimitiveError::Cancelled,
            ));
        }
        self.safe_eject_count += 1;
        self.facts.media_present = false;
        self.facts.media_fingerprint = None;
        if self.eject_completion_unknown {
            Err(PrimitiveFailure::completion_unknown(
                HostPrimitiveError::TimedOut,
            ))
        } else {
            Ok(())
        }
    }

    /// Records only the explicitly requested normal or forced primitive.
    fn eject_exact(
        &mut self,
        expected: &HostVolumeBinding,
        force: bool,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        if force {
            self.force_eject_count += 1;
        } else {
            self.safe_eject_count += 1;
        }
        self.facts.media_present = false;
        self.facts.media_fingerprint = None;
        if self.eject_completion_unknown {
            Err(PrimitiveFailure::completion_unknown(
                HostPrimitiveError::TimedOut,
            ))
        } else {
            Ok(())
        }
    }

    /// Records a nonzero MBR signature and optional completion uncertainty.
    fn create_single_partition(
        &mut self,
        expected: &HostVolumeBinding,
        mbr_signature: u32,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        if mbr_signature == 0 {
            return Err(PrimitiveFailure::not_attempted(HostPrimitiveError::Other));
        }
        self.layout_change_count += 1;
        self.last_mbr_signature = Some(mbr_signature);
        if self.layout_completion_unknown {
            Err(PrimitiveFailure::completion_unknown(
                HostPrimitiveError::TimedOut,
            ))
        } else {
            Ok(())
        }
    }

    /// Records one selected filesystem format.
    fn format_partition(
        &mut self,
        expected: &HostVolumeBinding,
        _filesystem: FileSystem,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        self.format_count += 1;
        if self.format_not_attempted_after_layout {
            Err(PrimitiveFailure::not_attempted(HostPrimitiveError::Busy))
        } else {
            Ok(())
        }
    }

    /// Proves departure unless the adversarial fixture withholds evidence.
    fn verify_eject_departure(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        if expected != &self.binding {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        if self.eject_departure_unconfirmed || self.facts.media_present {
            Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::TimedOut,
            ))
        } else {
            Ok(())
        }
    }

    /// Proves one new selected filesystem unless adversarial evidence is absent.
    fn verify_format_rediscovery(
        &mut self,
        expected: &HostVolumeBinding,
        _filesystem: FileSystem,
        previous_capacity: u64,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        if self.format_postcondition_unconfirmed || self.facts.capacity_bytes != previous_capacity {
            Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::TimedOut,
            ))
        } else {
            Ok(())
        }
    }

    /// Records mandatory invalidation after layout dispatch begins.
    fn invalidate_for_rediscovery(&mut self) {
        self.session_invalidated = true;
    }

    /// Writes one collision-free exact-serial preference.
    fn set_drive_letter_exact(
        &mut self,
        expected: &HostVolumeBinding,
        letter: char,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        if self.letter_collisions.contains(&letter) {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::DriveLetterInUse,
            ));
        }
        self.set_drive_letter_count += 1;
        self.current_drive_letter = Some(letter);
        self.mapping_app_owned = true;
        Ok(())
    }

    /// Removes only the fixture's exact application-owned preference.
    fn reset_drive_letter_exact(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_boundary(expected)?;
        if self.current_drive_letter.is_some() && !self.mapping_app_owned {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::MappingNotOwned,
            ));
        }
        self.reset_drive_letter_count += 1;
        self.current_drive_letter = None;
        self.mapping_app_owned = false;
        Ok(())
    }
}
