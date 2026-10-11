// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service host-operation adapter for this platform.

use super::*;

impl crate::platform::PlatformDeviceHandle for LinuxDeviceHandle {
    /// Reads the validated exact mount's native volume label.
    fn host_volume_label(
        &mut self,
    ) -> Result<Option<crate::model::VolumeLabel>, crate::operations::PrimitiveFailure> {
        crate::model::VolumeLabel::new(
            self.device
                .volume_label()
                .map_err(linux_host_not_attempted)?,
        )
        .map(Some)
        .map_err(|_| linux_host_not_attempted(rdx_linux_native::NativeError::EvidenceIncomplete))
    }

    /// Changes only the exact mounted cartridge's label with native readback.
    fn set_volume_label_exact(
        &mut self,
        label: &crate::model::VolumeLabel,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_linux_host_outcome(self.device.set_volume_label(label.as_str()))
    }
    /// Executes one trusted immutable command through the already-open sg lease.
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        let packet = match build_sg_io(command) {
            Ok(packet) => packet,
            Err(_) => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        let operation = match native_operation(&packet) {
            Ok(operation) => operation,
            Err(_) => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        let completion = match self.device.execute(operation) {
            rdx_linux_native::Completion::NotAttempted(error) => {
                NativeSgCompletion::not_attempted(map_native_io_failure(error))
            }
            rdx_linux_native::Completion::AttemptedError(error) => {
                NativeSgCompletion::attempted_error(map_native_io_failure(error))
            }
            rdx_linux_native::Completion::Device {
                status,
                masked_status,
                message_status,
                host_status,
                driver_status,
                info,
                residual,
                data,
                sense_reported_length,
                sense,
            } => NativeSgCompletion::device(
                SgIoStatus::new(
                    status,
                    masked_status,
                    message_status,
                    host_status,
                    driver_status,
                    info,
                ),
                residual,
                data,
                sense_reported_length,
                sense,
            ),
        };
        convert_sg_completion(&packet, completion)
    }

    /// Returns conservative facts from exact retained block and mount authorities.
    fn host_volume_facts(
        &mut self,
    ) -> Result<crate::operations::HostVolumeFacts, crate::operations::PrimitiveFailure> {
        let volumes = match self.device.pin_volumes() {
            Ok(volumes) => volumes,
            Err(error) => {
                let absence = absent_cartridge_facts(error);
                return absence.ok_or_else(|| linux_host_not_attempted(error));
            }
        };
        let present = volumes.block_count() > 0;
        let mounted_facts = volumes.mounted_facts();
        let media_facts = volumes.media_facts();
        let media_fingerprint = media_facts.and_then(|(writable, capacity)| {
            volumes.media_identity_material().map(|material| {
                crate::platform::media_fingerprint(
                    b"linux-sg-block-v1",
                    capacity,
                    writable,
                    material,
                )
            })
        });
        Ok(crate::operations::HostVolumeFacts {
            media_present: present,
            writable: media_facts.is_some_and(|facts| facts.0),
            mounted: volumes.mount_count() > 0,
            free_bytes: mounted_facts.map_or(0, |facts| facts.1),
            capacity_bytes: media_facts.map_or(0, |facts| facts.1),
            filesystem: volumes.mounted_filesystem().map(service_filesystem),
            media_fingerprint,
            topology: if volumes.mutation_topology_safe() {
                crate::operations::VolumeTopology::Simple
            } else {
                crate::operations::VolumeTopology::BootOrSystem
            },
        })
    }

    /// Checks fixed root-owned partitioning and filesystem dependencies.
    fn preflight_format(
        &mut self,
        filesystem: crate::operations::FileSystem,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        self.device
            .preflight_format(linux_filesystem(filesystem)?)
            .map_err(linux_host_not_attempted)
    }

    /// Runs the exact retained mounted-volume file test and maps cleanup separately.
    fn write_read_file(
        &mut self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<crate::operations::WriteReadPrimitiveResult, crate::operations::PrimitiveFailure>
    {
        let volumes = self
            .device
            .pin_volumes()
            .map_err(linux_host_not_attempted)?;
        let (operation, operation_certainty, cleanup) =
            volumes.write_read_file(filename, bytes).into_parts();
        Ok(crate::operations::WriteReadPrimitiveResult {
            operation: operation.map_err(|_| {
                map_linux_host_outcome(operation_certainty)
                    .expect_err("failed operation has failure certainty")
            }),
            cleanup: map_linux_cleanup(cleanup),
        })
    }

    /// Unmounts every exact retained mount for a later format boundary.
    fn unmount_exact_volumes(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        let volumes = self
            .device
            .pin_volumes()
            .map_err(linux_host_not_attempted)?;
        map_linux_host_outcome(volumes.unmount_all())
    }

    /// Retains exact block authority across safe unmount and SG media eject.
    fn safe_eject_exact(
        &mut self,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        let volumes = self
            .device
            .pin_volumes()
            .map_err(linux_host_not_attempted)?;
        map_linux_host_outcome(volumes.safe_eject_observed(after_unmount))
    }

    /// Dispatches only the distinct externally confirmed force-eject path.
    fn eject_exact(&mut self, force: bool) -> Result<(), crate::operations::PrimitiveFailure> {
        if !force {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::Other,
            ));
        }
        map_linux_host_outcome(self.device.force_eject())
    }

    /// Applies one exact MBR layout through fixed-argv `sfdisk`.
    fn create_single_partition(
        &mut self,
        mbr_signature: u32,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_linux_host_outcome(self.device.create_single_partition(mbr_signature))
    }

    /// Formats the sole exact new partition through the selected fixed mkfs tool.
    fn format_partition(
        &mut self,
        filesystem: crate::operations::FileSystem,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_linux_host_outcome(self.device.format_partition(linux_filesystem(filesystem)?))
    }

    /// Waits for authoritative exact-cartridge absence after eject dispatch.
    fn verify_eject_departure(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        self.device.verify_eject_departure().map_err(|error| {
            crate::operations::PrimitiveFailure::completion_unknown(map_linux_host_error(error))
        })
    }

    /// Proves one exact newly mounted filesystem and unchanged cartridge capacity.
    fn verify_format_rediscovery(
        &mut self,
        filesystem: crate::operations::FileSystem,
        previous_capacity: u64,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        self.device
            .verify_format_rediscovery(linux_filesystem(filesystem)?, previous_capacity)
            .map_err(|error| {
                crate::operations::PrimitiveFailure::completion_unknown(map_linux_host_error(error))
            })
    }
}

/// Maps the service filesystem enum into the companion's closed semantic enum.
#[cfg(target_os = "linux")]
const fn linux_filesystem(
    filesystem: crate::operations::FileSystem,
) -> Result<rdx_linux_native::HostFilesystem, crate::operations::PrimitiveFailure> {
    Ok(match filesystem {
        crate::operations::FileSystem::Ntfs => rdx_linux_native::HostFilesystem::Ntfs,
        crate::operations::FileSystem::ExFat => rdx_linux_native::HostFilesystem::ExFat,
        crate::operations::FileSystem::Linux(selected)
        | crate::operations::FileSystem::MacOs(selected) => match selected {
            crate::model::Filesystem::Ext2 => rdx_linux_native::HostFilesystem::Ext2,
            crate::model::Filesystem::Ext3 => rdx_linux_native::HostFilesystem::Ext3,
            crate::model::Filesystem::Ext4 => rdx_linux_native::HostFilesystem::Ext4,
            crate::model::Filesystem::Xfs => rdx_linux_native::HostFilesystem::Xfs,
            crate::model::Filesystem::Btrfs => rdx_linux_native::HostFilesystem::Btrfs,
            crate::model::Filesystem::F2fs => rdx_linux_native::HostFilesystem::F2fs,
            crate::model::Filesystem::Fat16 => rdx_linux_native::HostFilesystem::Fat16,
            crate::model::Filesystem::Fat32 => rdx_linux_native::HostFilesystem::Fat32,
            _ => {
                return Err(crate::operations::PrimitiveFailure::not_attempted(
                    crate::operations::HostPrimitiveError::UnsupportedPlatform,
                ));
            }
        },
    })
}

/// Maps pre-dispatch Linux native evidence into the shared host contract.
#[cfg(target_os = "linux")]
fn linux_host_not_attempted(
    error: rdx_linux_native::NativeError,
) -> crate::operations::PrimitiveFailure {
    crate::operations::PrimitiveFailure::not_attempted(map_linux_host_error(error))
}

/// Maps a closed Linux mutation without losing dispatch certainty.
#[cfg(target_os = "linux")]
fn map_linux_host_outcome(
    outcome: rdx_linux_native::HostOperationOutcome,
) -> Result<(), crate::operations::PrimitiveFailure> {
    use rdx_linux_native::HostOperationOutcome;

    match outcome {
        HostOperationOutcome::Succeeded => Ok(()),
        HostOperationOutcome::NotAttempted(error) => Err(
            crate::operations::PrimitiveFailure::not_attempted(map_linux_host_error(error)),
        ),
        HostOperationOutcome::DefinitelyRejected(error) => Err(
            crate::operations::PrimitiveFailure::definitely_rejected(map_linux_host_error(error)),
        ),
        HostOperationOutcome::CompletionUnknown(error) => Err(
            crate::operations::PrimitiveFailure::completion_unknown(map_linux_host_error(error)),
        ),
    }
}

/// Maps cleanup outcome into the shared independent cleanup contract.
#[cfg(target_os = "linux")]
fn map_linux_cleanup(
    outcome: rdx_linux_native::HostOperationOutcome,
) -> Result<(), crate::operations::PrimitiveFailure> {
    map_linux_host_outcome(outcome)
}

/// Maps sanitized Linux native errors into shared host causes.
#[cfg(target_os = "linux")]
const fn map_linux_host_error(
    error: rdx_linux_native::NativeError,
) -> crate::operations::HostPrimitiveError {
    use crate::operations::HostPrimitiveError;
    use rdx_linux_native::NativeError;

    match error {
        NativeError::Busy => HostPrimitiveError::Busy,
        NativeError::DependencyMissing => HostPrimitiveError::DependencyMissing,
        NativeError::Interrupted => HostPrimitiveError::Cancelled,
        NativeError::TimedOut => HostPrimitiveError::TimedOut,
        NativeError::DeviceRemoved | NativeError::NoMedia | NativeError::EvidenceIncomplete => {
            HostPrimitiveError::StaleBinding
        }
        NativeError::UnsupportedPlatform => HostPrimitiveError::UnsupportedPlatform,
        NativeError::InvalidRequest
        | NativeError::AccessDenied
        | NativeError::EnumerationFailed
        | NativeError::ResourceLimit
        | NativeError::Other => HostPrimitiveError::Other,
    }
}

/// Fresh MEDIUM NOT PRESENT describes an empty retained dock, never a removed dock.
fn absent_cartridge_facts(
    error: rdx_linux_native::NativeError,
) -> Option<crate::operations::HostVolumeFacts> {
    (error == rdx_linux_native::NativeError::NoMedia).then_some(
        crate::operations::HostVolumeFacts {
            media_present: false,
            writable: false,
            mounted: false,
            free_bytes: 0,
            capacity_bytes: 0,
            filesystem: None,
            media_fingerprint: None,
            topology: crate::operations::VolumeTopology::Simple,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only explicit same-dock no-media sense can become a visible empty dock.
    #[test]
    fn empty_dock_facts_require_explicit_no_media() {
        let facts =
            absent_cartridge_facts(rdx_linux_native::NativeError::NoMedia).expect("empty dock");
        assert!(!facts.media_present && !facts.mounted && !facts.writable);
        assert_eq!(facts.capacity_bytes, 0);
        assert_eq!(facts.free_bytes, 0);
        assert!(facts.media_fingerprint.is_none() && facts.filesystem.is_none());
        for error in [
            rdx_linux_native::NativeError::DeviceRemoved,
            rdx_linux_native::NativeError::EvidenceIncomplete,
            rdx_linux_native::NativeError::TimedOut,
        ] {
            assert!(absent_cartridge_facts(error).is_none());
        }
    }
}

/// Publishes only recognized mounted drivers as closed service personalities.
#[cfg(target_os = "linux")]
fn service_filesystem(fs: rdx_linux_native::HostFilesystem) -> crate::operations::FileSystem {
    use crate::{model::Filesystem, operations::FileSystem};
    use rdx_linux_native::HostFilesystem as Native;
    match fs {
        Native::Ntfs => FileSystem::Ntfs,
        Native::ExFat => FileSystem::ExFat,
        Native::Ext2 => FileSystem::Linux(Filesystem::Ext2),
        Native::Ext3 => FileSystem::Linux(Filesystem::Ext3),
        Native::Ext4 => FileSystem::Linux(Filesystem::Ext4),
        Native::Xfs => FileSystem::Linux(Filesystem::Xfs),
        Native::Btrfs => FileSystem::Linux(Filesystem::Btrfs),
        Native::F2fs => FileSystem::Linux(Filesystem::F2fs),
        Native::Fat16 => FileSystem::MacOs(Filesystem::Fat16),
        Native::Fat32 => FileSystem::MacOs(Filesystem::Fat32),
    }
}
