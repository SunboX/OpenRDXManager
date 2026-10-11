// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Format completion rebinds mount associations while preserving exact identity.

use super::layout::disk_capacity;
use super::volumes::ScannedVolumes;
use super::*;

#[cfg(test)]
mod tests;

/// One exact layout written by this handle; never populated by discovery.
pub(super) struct CreatedLayout {
    stamp: layout::DiskLayoutStamp,
    partition: PARTITION_INFORMATION_EX,
    medium: Vec<u8>,
    capacity: u64,
}

impl CreatedLayout {
    /// Rejects a stale Windows volume stack even when the disk layout has settled.
    fn matches_volume(&self, topology: &crate::VolumeTopology, disk: u32) -> bool {
        let [extent] = topology.extents.as_slice() else {
            return false;
        };
        topology.storage.device_number == disk
            && topology.storage.partition_number == 1
            && extent.disk_number == disk
            && extent.starting_offset == self.partition.StartingOffset
            && extent.extent_length == self.partition.PartitionLength
    }

    /// Rejects any partition/identity/extent change beyond Windows bookkeeping.
    fn matches(
        &self,
        stamp: layout::DiskLayoutStamp,
        entries: &[PARTITION_INFORMATION_EX],
    ) -> bool {
        if self.stamp != stamp || entries.iter().any(|p| p.PartitionLength < 0) {
            return false;
        }
        let present: Vec<_> = entries.iter().filter(|p| p.PartitionLength > 0).collect();
        let [current] = present.as_slice() else {
            return false;
        };
        let expected = &self.partition;
        if current.PartitionStyle != expected.PartitionStyle
            || current.PartitionNumber != 1
            || current.IsServicePartition
            || current.StartingOffset != expected.StartingOffset
            || current.PartitionLength != expected.PartitionLength
        {
            return false;
        }
        if current.PartitionStyle == PARTITION_STYLE_GPT {
            // SAFETY: both partition discriminants are checked and equal.
            let (before, after) = unsafe { (expected.Anonymous.Gpt, current.Anonymous.Gpt) };
            before.PartitionType == after.PartitionType
                && before.PartitionId == after.PartitionId
                && after.Attributes.0 == 0
        } else if current.PartitionStyle == PARTITION_STYLE_MBR {
            // SAFETY: both partition discriminants are checked and equal.
            let (before, after) = unsafe { (expected.Anonymous.Mbr, current.Anonymous.Mbr) };
            before.PartitionType == after.PartitionType
                && !after.BootIndicator
                && before.HiddenSectors == after.HiddenSectors
        } else {
            false
        }
    }
}

impl NativeDevice {
    /// Clears any prior one-shot continuation before another layout attempt.
    pub(super) fn clear_created_layout(&self) -> Result<(), NativeError> {
        *self.pending_format.lock().map_err(|_| NativeError::Other)? = None;
        Ok(())
    }

    /// Records only the exact successful layout IOCTL's generated identifiers.
    pub(super) fn remember_created_layout(
        &self,
        created: &DRIVE_LAYOUT_INFORMATION_EX,
        capacity: u64,
        medium: Vec<u8>,
    ) -> Result<(), NativeError> {
        let proof = CreatedLayout {
            stamp: layout::layout_stamp(created)?,
            partition: created.PartitionEntry[0],
            capacity,
            medium,
        };
        *self.pending_format.lock().map_err(|_| NativeError::Other)? = Some(proof);
        Ok(())
    }

    /// Proves dock, cartridge, capacity and the exact generated layout before formatting.
    fn revalidate_created_layout(&self, proof: &CreatedLayout) -> Result<(), NativeError> {
        self.revalidate_format_media(&proof.medium, proof.capacity)?;
        let (stamp, entries) = layout::disk_layout(kernel_handle(&self.handle))?;
        if !proof.matches(stamp, &entries) {
            return Err(NativeError::DeviceRemoved);
        }
        self.revalidate_format_media(&proof.medium, proof.capacity)
    }

    /// Waits for the sole new exact volume and formats it once through VDS.
    pub(crate) fn format_partition(&self, filesystem: HostFilesystem) -> HostOperationOutcome {
        let proof = match self.pending_format.lock() {
            Ok(mut pending) => match pending.take() {
                Some(proof) => proof,
                None => return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest),
            },
            Err(_) => return HostOperationOutcome::NotAttempted(NativeError::Other),
        };
        for _ in 0..100 {
            if let Err(error) = self.revalidate_created_layout(&proof) {
                return HostOperationOutcome::CompletionUnknown(error);
            }
            match volumes::pin_disk_volumes(self.identity.disk_number()) {
                Ok(scanned) if scanned.leases.len() == 1 => {
                    match scanned.leases[0].format_topology() {
                        Ok(topology)
                            if proof.matches_volume(&topology, self.identity.disk_number()) => {}
                        Ok(_) => {
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        Err(error) => return HostOperationOutcome::CompletionUnknown(error),
                    }
                    return match self.format_and_rebind(scanned, filesystem, &proof) {
                        Ok(()) => HostOperationOutcome::Succeeded,
                        Err(error) => HostOperationOutcome::CompletionUnknown(error),
                    };
                }
                Ok(_) | Err(NativeError::DeviceRemoved | NativeError::EnumerationFailed) => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => return HostOperationOutcome::CompletionUnknown(error),
            }
        }
        HostOperationOutcome::CompletionUnknown(NativeError::TimedOut)
    }

    /// Separates confirmed filesystem dispatch from bounded, read-only remount
    /// verification. A failed post-format check never dispatches a second format.
    fn format_and_rebind(
        &self,
        scanned: ScannedVolumes,
        filesystem: HostFilesystem,
        proof: &CreatedLayout,
    ) -> Result<(), NativeError> {
        let medium = self.media_identity_material()?;
        let capacity = disk_capacity(kernel_handle(&self.handle))?;
        self.revalidate_volume_leases(&scanned.leases)?;
        self.revalidate_created_layout(proof)?;
        if !proof.matches_volume(
            &scanned.leases[0].format_topology()?,
            self.identity.disk_number(),
        ) {
            return Err(NativeError::DeviceRemoved);
        }
        let expected = scanned.leases[0].format(filesystem)?;
        // The old filesystem stack and its mount associations may be replaced
        // by VDS. Keep only immutable identity evidence after successful VDS.
        drop(scanned);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            self.revalidate_format_media(&medium, capacity)?;
            match volumes::pin_disk_volumes(self.identity.disk_number()) {
                Ok(current) if current.leases.len() == 1 => {
                    // This check allows only the mount snapshot to change. A
                    // different GUID, disk/partition identity or extent fails.
                    current.leases[0].revalidate_after_format(&expected)?;
                    match self.revalidate_volume_leases(&current.leases) {
                        Ok(()) => {
                            self.revalidate_format_media(&medium, capacity)?;
                            return Ok(());
                        }
                        // Mount assignment can race a fresh scan. Retry only
                        // read-only rebinding, with immutable identity and
                        // medium/capacity proofs still required on every loop.
                        Err(NativeError::DeviceRemoved | NativeError::EnumerationFailed)
                            if std::time::Instant::now() < deadline => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(current) if current.leases.len() > 1 => {
                    return Err(NativeError::EvidenceIncomplete);
                }
                Ok(_) | Err(NativeError::DeviceRemoved | NativeError::EnumerationFailed)
                    if std::time::Instant::now() < deadline => {}
                Ok(_) => return Err(NativeError::TimedOut),
                Err(error) => return Err(error),
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Preserves the retained dock, cartridge generation and full capacity
    /// around every fresh post-format volume scan.
    fn revalidate_format_media(&self, medium: &[u8], capacity: u64) -> Result<(), NativeError> {
        self.revalidate_exact()?;
        if self.media_identity_material()? != medium
            || disk_capacity(kernel_handle(&self.handle))? != capacity
        {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(())
    }
}
