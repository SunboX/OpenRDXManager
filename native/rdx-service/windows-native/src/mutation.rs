// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable orchestration for closed, immediate Windows volume mutations.

use std::collections::BTreeSet;

use super::{NativeError, VolumeMutationOutcome, VolumeTopology};

const MAX_INVENTORY_VOLUMES: usize = 256;
const MAX_VOLUME_KEY_UNITS: usize = 1_024;

/// One complete inspected volume record with an internal enumeration identity.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct VolumeRecord {
    key: Vec<u16>,
    topology: VolumeTopology,
    drive_letters: Vec<char>,
    mount_paths: Vec<Vec<u16>>,
    target: bool,
}

impl VolumeRecord {
    /// Builds a bounded internal record and canonicalizes its mount letters.
    #[cfg(test)]
    pub(super) fn new(
        key: Vec<u16>,
        topology: VolumeTopology,
        mut drive_letters: Vec<char>,
        target: bool,
    ) -> Result<Self, NativeError> {
        if key.is_empty()
            || key.len() > MAX_VOLUME_KEY_UNITS
            || drive_letters
                .iter()
                .any(|letter| !letter.is_ascii_uppercase())
        {
            return Err(NativeError::EnumerationFailed);
        }
        drive_letters.sort_unstable();
        drive_letters.dedup();
        let mount_paths = drive_letters
            .iter()
            .map(|letter| vec![*letter as u16, ':' as u16, '\\' as u16])
            .collect();
        Ok(Self {
            key,
            topology,
            drive_letters,
            mount_paths,
            target,
        })
    }

    /// Builds a production record retaining every exact letter or folder mount path.
    #[cfg(windows)]
    pub(super) fn new_with_mount_paths(
        key: Vec<u16>,
        topology: VolumeTopology,
        mut mount_paths: Vec<Vec<u16>>,
        target: bool,
    ) -> Result<Self, NativeError> {
        if key.is_empty()
            || key.len() > MAX_VOLUME_KEY_UNITS
            || mount_paths.iter().any(|path| path.len() < 3)
        {
            return Err(NativeError::EnumerationFailed);
        }
        mount_paths.sort_unstable();
        if mount_paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(NativeError::EnumerationFailed);
        }
        let mut drive_letters = mount_paths
            .iter()
            .filter_map(|path| {
                (path.len() == 3)
                    .then(|| char::from_u32(u32::from(path[0])))
                    .flatten()
                    .map(|letter| letter.to_ascii_uppercase())
            })
            .collect::<Vec<_>>();
        drive_letters.sort_unstable();
        drive_letters.dedup();
        Ok(Self {
            key,
            topology,
            drive_letters,
            mount_paths,
            target,
        })
    }

    /// Returns the private enumeration key only inside the native boundary.
    #[cfg(windows)]
    pub(super) fn key(&self) -> &[u16] {
        &self.key
    }

    /// Returns the normalized mount letters for an internal association query.
    #[cfg(windows)]
    pub(super) fn drive_letters(&self) -> &[char] {
        &self.drive_letters
    }

    /// Returns all exact mount paths, including folder mount points.
    #[cfg(windows)]
    pub(super) fn mount_paths(&self) -> &[Vec<u16>] {
        &self.mount_paths
    }

    /// Revalidates complete topology and mount association on one retained handle.
    #[cfg(any(windows, test))]
    pub(super) fn revalidate(
        &self,
        topology: &VolumeTopology,
        mount_paths: &[Vec<u16>],
    ) -> Result<(), NativeError> {
        if &self.topology == topology && self.mount_paths == mount_paths {
            Ok(())
        } else {
            Err(NativeError::DeviceRemoved)
        }
    }

    /// Rebinds after confirmed format completion without treating remount as
    /// cartridge replacement. GUID, full storage identity and every extent must
    /// remain exact; the caller separately validates the fresh mount snapshot.
    #[cfg(any(windows, test))]
    pub(super) fn revalidate_after_format(&self, current: &Self) -> Result<(), NativeError> {
        if self.target
            && current.target
            && self.key == current.key
            && self.topology == current.topology
        {
            Ok(())
        } else {
            Err(NativeError::DeviceRemoved)
        }
    }
}

impl std::fmt::Debug for VolumeRecord {
    /// Redacts the internal volume identity and complete topology.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VolumeRecord")
            .field("target", &self.target)
            .field("drive_letter_count", &self.drive_letters.len())
            .field("identity", &"<private>")
            .finish()
    }
}

/// Canonical complete set from one bounded FindFirst/FindNext enumeration.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct VolumeInventory {
    records: Vec<VolumeRecord>,
}

impl VolumeInventory {
    /// Sorts by private volume identity and rejects duplicates or mount ambiguity.
    pub(super) fn new(mut records: Vec<VolumeRecord>) -> Result<Self, NativeError> {
        if records.is_empty() || records.len() > MAX_INVENTORY_VOLUMES {
            return Err(NativeError::EnumerationFailed);
        }
        records.sort_by(|left, right| left.key.cmp(&right.key));
        if records.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(NativeError::EnumerationFailed);
        }
        let mut assigned_letters = BTreeSet::new();
        let mut assigned_paths = BTreeSet::new();
        for record in &records {
            for path in &record.mount_paths {
                if !assigned_paths.insert(path.clone()) {
                    return Err(NativeError::EnumerationFailed);
                }
            }
            for letter in &record.drive_letters {
                if !assigned_letters.insert(*letter) {
                    return Err(NativeError::EnumerationFailed);
                }
            }
        }
        Ok(Self { records })
    }

    /// Proves the selected uppercase drive letter belongs to exactly one target volume.
    #[cfg(test)]
    fn selected_target_matches(&self, selected_drive_letter: char) -> Result<(), NativeError> {
        if !selected_drive_letter.is_ascii_uppercase() {
            return Err(NativeError::InvalidRequest);
        }
        let matches = self
            .records
            .iter()
            .filter(|record| record.target && record.drive_letters.contains(&selected_drive_letter))
            .count();
        if matches == 1 {
            Ok(())
        } else {
            Err(NativeError::DeviceRemoved)
        }
    }
}

impl std::fmt::Debug for VolumeInventory {
    /// Reports only a bounded count while redacting all identities and topology.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VolumeInventory")
            .field("volume_count", &self.records.len())
            .field("records", &"<private>")
            .finish()
    }
}

/// Closed native actions required by the safe-dismount semantic operation.
pub(super) trait VolumeMutationIo {
    /// Revalidates the exact retained parent instance and physical handle.
    fn revalidate_parent(&mut self) -> Result<(), NativeError>;
    /// Fresh-enumerates and fully inspects every current volume.
    fn scan_complete(&mut self) -> Result<VolumeInventory, NativeError>;
    /// Requeries every original retained handle's topology and mount association.
    fn revalidate_retained_volumes(&mut self) -> Result<(), NativeError>;
    /// Locks every retained target volume without exposing its handle.
    fn lock_retained_volumes(&mut self) -> Result<(), NativeError>;
    /// Dismounts every already-locked target volume.
    fn dismount_retained_volumes(&mut self) -> Result<(), NativeError>;
}

/// Executes one consuming safe dismount immediately behind the complete guard.
#[cfg(test)]
pub(super) fn execute_safe_dismount(
    io: &mut impl VolumeMutationIo,
    retained: &VolumeInventory,
    selected_drive_letter: char,
) -> VolumeMutationOutcome {
    if !selected_drive_letter.is_ascii_uppercase() {
        return VolumeMutationOutcome::NotAttempted(NativeError::InvalidRequest);
    }
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    let first = match io.scan_complete() {
        Ok(inventory) => inventory,
        Err(error) => return VolumeMutationOutcome::NotAttempted(error),
    };
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    let second = match io.scan_complete() {
        Ok(inventory) => inventory,
        Err(error) => return VolumeMutationOutcome::NotAttempted(error),
    };
    if &first != retained || &second != retained || first != second {
        return VolumeMutationOutcome::NotAttempted(NativeError::DeviceRemoved);
    }
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = retained.selected_target_matches(selected_drive_letter) {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_retained_volumes() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.lock_retained_volumes() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_retained_volumes() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    match io.dismount_retained_volumes() {
        Ok(()) => VolumeMutationOutcome::Succeeded,
        Err(error) => VolumeMutationOutcome::CompletionUnknown(error),
    }
}

/// Executes exact all-target dismount without assuming a drive-letter mount.
#[cfg(any(windows, test))]
pub(super) fn execute_safe_dismount_all(
    io: &mut impl VolumeMutationIo,
    retained: &VolumeInventory,
) -> VolumeMutationOutcome {
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    let first = match io.scan_complete() {
        Ok(inventory) => inventory,
        Err(error) => return VolumeMutationOutcome::NotAttempted(error),
    };
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    let second = match io.scan_complete() {
        Ok(inventory) => inventory,
        Err(error) => return VolumeMutationOutcome::NotAttempted(error),
    };
    if &first != retained || &second != retained || first != second {
        return VolumeMutationOutcome::NotAttempted(NativeError::DeviceRemoved);
    }
    if let Err(error) = io.revalidate_retained_volumes() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.lock_retained_volumes() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_retained_volumes() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_parent() {
        return VolumeMutationOutcome::NotAttempted(error);
    }
    match io.dismount_retained_volumes() {
        Ok(()) => VolumeMutationOutcome::Succeeded,
        Err(error) => VolumeMutationOutcome::CompletionUnknown(error),
    }
}

/// Dismounts exact retained volumes and dispatches layout while their locks live.
/// Mount-point associations may remain after FSCTL_DISMOUNT_VOLUME; exclusive
/// locks, fresh complete inventory and retained-handle identity authorize layout.
/// The caller must own the retained volume handles until this function returns.
pub(super) fn execute_locked_layout(
    io: &mut impl VolumeMutationIo,
    retained: &VolumeInventory,
    dispatch: impl FnOnce() -> super::HostOperationOutcome,
) -> super::HostOperationOutcome {
    match execute_safe_dismount_all(io, retained) {
        VolumeMutationOutcome::NotAttempted(error) => {
            return super::HostOperationOutcome::NotAttempted(error);
        }
        VolumeMutationOutcome::CompletionUnknown(error) => {
            return super::HostOperationOutcome::CompletionUnknown(error);
        }
        VolumeMutationOutcome::Succeeded => {}
    }
    if let Err(error) = io.revalidate_retained_volumes() {
        return super::HostOperationOutcome::NotAttempted(error);
    }
    if let Err(error) = io.revalidate_parent() {
        return super::HostOperationOutcome::NotAttempted(error);
    }
    dispatch()
}
