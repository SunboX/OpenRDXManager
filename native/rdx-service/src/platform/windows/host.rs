// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service host-operation adapter for this platform.

use super::*;

impl crate::platform::PlatformDeviceHandle for WindowsDeviceHandle {
    /// Returns a display-safe label without exporting native volume paths.
    fn host_volume_label(
        &mut self,
    ) -> Result<Option<crate::model::VolumeLabel>, crate::operations::PrimitiveFailure> {
        let label = self
            .device
            .volume_label()
            .map_err(windows_host_not_attempted)?;
        crate::model::VolumeLabel::new(label)
            .map(Some)
            .map_err(|_| {
                crate::operations::PrimitiveFailure::not_attempted(
                    crate::operations::HostPrimitiveError::Other,
                )
            })
    }
    /// Runs the exact-volume rename with native readback and mutation certainty.
    fn set_volume_label_exact(
        &mut self,
        label: &crate::model::VolumeLabel,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_windows_host_outcome(self.device.set_volume_label(label.as_str()))
    }

    /// Executes one trusted immutable command through the already-open disk lease.
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        let packet = match build_scsi_pass_through(command) {
            Ok(packet) => packet,
            Err(_) => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        let operation = match native_operation(&packet) {
            Ok(operation) => operation,
            Err(_) => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        let completion = match self.device.execute(operation) {
            rdx_windows_native::Completion::NotAttempted(error) => {
                NativeScsiCompletion::not_attempted(map_native_io_failure(error))
            }
            rdx_windows_native::Completion::AttemptedError(error) => {
                NativeScsiCompletion::attempted_error(map_native_io_failure(error))
            }
            rdx_windows_native::Completion::Device {
                scsi_status,
                transferred_length,
                data,
                sense_reported_length,
                sense,
            } => NativeScsiCompletion::device(
                scsi_status,
                transferred_length,
                data,
                sense_reported_length,
                sense,
            ),
        };
        if packet.semantic == WindowsSemanticCommand::SelfTest {
            eprintln!(
                "openrdx-hardware: trace {}",
                super::diagnostics::self_test_code(&parse_scsi_result(&packet, completion.clone()))
            );
        }
        convert_scsi_completion(&packet, completion)
    }

    /// Binds the exact validated dock-serial key without applying arrival policy.
    fn bind_serial_mapping_key(
        &mut self,
        serial_key: &str,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        if serial_key.len() != 64
            || !serial_key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::StaleBinding,
            ));
        }
        self.serial_mapping_key = Some(serial_key.to_owned());
        Ok(())
    }

    /// Applies a stored preference only from the authoritative discovery arrival path.
    fn apply_drive_letter_preference_on_arrival(
        &mut self,
        serial_key: &str,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_windows_drive_letter_outcome(
            self.device.apply_drive_letter_preference(serial_key),
            false,
        )
    }

    /// Returns conservative exact Windows volume membership facts.
    fn host_volume_facts(
        &mut self,
    ) -> Result<crate::operations::HostVolumeFacts, crate::operations::PrimitiveFailure> {
        let facts = self
            .device
            .volume_facts()
            .map_err(windows_host_not_attempted)?;
        windows_volume_facts(&mut self.device, facts)
    }

    /// Admits only a separately proven non-system Mac data layout for formatting.
    fn host_format_volume_facts(
        &mut self,
    ) -> Result<crate::operations::HostVolumeFacts, crate::operations::PrimitiveFailure> {
        let facts = self
            .device
            .format_volume_facts()
            .map_err(windows_host_not_attempted)?;
        windows_volume_facts(&mut self.device, facts)
    }

    /// Enumerates sorted free letters through the fixed native Windows source.
    fn available_drive_letters(
        &mut self,
    ) -> Result<Vec<crate::model::DriveLetter>, crate::operations::PrimitiveFailure> {
        rdx_windows_native::available_drive_letters()
            .map_err(windows_host_not_attempted)?
            .into_iter()
            .map(|letter| {
                crate::model::DriveLetter::new(letter).map_err(|_| {
                    crate::operations::PrimitiveFailure::not_attempted(
                        crate::operations::HostPrimitiveError::Other,
                    )
                })
            })
            .collect()
    }

    /// Runs exact volume-GUID mounted file I/O with independent cleanup evidence.
    fn write_read_file(
        &mut self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<crate::operations::WriteReadPrimitiveResult, crate::operations::PrimitiveFailure>
    {
        let (operation, operation_certainty, cleanup) =
            self.device.write_read_file(filename, bytes).into_parts();
        Ok(crate::operations::WriteReadPrimitiveResult {
            operation: operation.map_err(|_| {
                map_windows_host_outcome(operation_certainty)
                    .expect_err("failed operation has failure certainty")
            }),
            cleanup: map_windows_host_outcome(cleanup),
        })
    }

    /// Proves Windows VDS availability before any unmount or layout change.
    fn preflight_format(
        &mut self,
        filesystem: crate::operations::FileSystem,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        self.device
            .preflight_format(windows_filesystem(filesystem)?)
            .map_err(windows_host_not_attempted)
    }

    /// Flushes, locks, and dismounts exact selected volumes without ejecting.
    fn unmount_exact_volumes(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        map_windows_host_outcome(self.device.unmount_all())
    }

    /// Runs the companion's retained-lock safe-eject operation.
    fn safe_eject_exact(
        &mut self,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_windows_host_outcome(self.device.safe_eject_observed(after_unmount))
    }

    /// Runs the separately confirmation-gated physical force-eject operation.
    fn eject_exact(&mut self, force: bool) -> Result<(), crate::operations::PrimitiveFailure> {
        if !force {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::Other,
            ));
        }
        map_windows_host_outcome(self.device.force_eject())
    }

    /// Applies one exact capacity-safe MBR or GPT layout through disk IOCTLs.
    fn create_single_partition(
        &mut self,
        mbr_signature: u32,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_windows_host_outcome(self.device.create_single_partition(mbr_signature))
    }

    /// Formats the sole newly discovered volume through VDS FormatEx2.
    fn format_partition(
        &mut self,
        filesystem: crate::operations::FileSystem,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        map_windows_host_outcome(
            self.device
                .format_partition(windows_filesystem(filesystem)?),
        )
    }

    /// Persists one collision-free exact-serial Windows preference.
    fn set_drive_letter_exact(
        &mut self,
        serial_key: &str,
        letter: char,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        if self.serial_mapping_key.as_deref() != Some(serial_key) {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::StaleBinding,
            ));
        }
        map_windows_drive_letter_outcome(self.device.set_drive_letter(serial_key, letter), false)
    }

    /// Removes only this application's current exact-serial preference.
    fn reset_drive_letter_exact(
        &mut self,
        serial_key: &str,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        if self.serial_mapping_key.as_deref() != Some(serial_key) {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::StaleBinding,
            ));
        }
        map_windows_drive_letter_outcome(self.device.reset_drive_letter(serial_key), true)
    }

    /// Waits for authoritative exact-cartridge absence after eject dispatch.
    fn verify_eject_departure(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        self.device.verify_eject_departure().map_err(|error| {
            crate::operations::PrimitiveFailure::completion_unknown(map_windows_host_error(error))
        })
    }

    /// Proves one exact newly mounted filesystem and unchanged capacity.
    fn verify_format_rediscovery(
        &mut self,
        filesystem: crate::operations::FileSystem,
        previous_capacity: u64,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        self.device
            .verify_format_rediscovery(windows_filesystem(filesystem)?, previous_capacity)
            .map_err(|error| {
                crate::operations::PrimitiveFailure::completion_unknown(map_windows_host_error(
                    error,
                ))
            })
    }
}

/// Projects private Windows facts without exporting paths or changing medium identity.
fn windows_volume_facts(
    device: &mut rdx_windows_native::WindowsDevice,
    (writable, mounted, free_bytes, capacity_bytes, topology_safe): (bool, bool, u64, u64, bool),
) -> Result<crate::operations::HostVolumeFacts, crate::operations::PrimitiveFailure> {
    let media_fingerprint = if capacity_bytes == 0 {
        None
    } else {
        let material = device
            .media_identity_material()
            .map_err(windows_host_not_attempted)?;
        Some(crate::platform::media_fingerprint(
            b"windows-storage-v1",
            capacity_bytes,
            writable,
            &material,
        ))
    };
    let filesystem = if mounted {
        device.volume_filesystem().ok().and_then(|value| {
            if value.eq_ignore_ascii_case("NTFS") {
                Some(crate::operations::FileSystem::Ntfs)
            } else if value.eq_ignore_ascii_case("exFAT") {
                Some(crate::operations::FileSystem::ExFat)
            } else {
                None
            }
        })
    } else {
        None
    };
    Ok(crate::operations::HostVolumeFacts {
        media_present: capacity_bytes > 0,
        writable,
        mounted,
        free_bytes,
        capacity_bytes,
        filesystem,
        media_fingerprint,
        topology: if topology_safe {
            crate::operations::VolumeTopology::Simple
        } else {
            crate::operations::VolumeTopology::BootOrSystem
        },
    })
}

/// Maps the service filesystem enum into the companion's closed semantic enum.
#[cfg(windows)]
const fn windows_filesystem(
    filesystem: crate::operations::FileSystem,
) -> Result<rdx_windows_native::HostFilesystem, crate::operations::PrimitiveFailure> {
    Ok(match filesystem {
        crate::operations::FileSystem::Ntfs => rdx_windows_native::HostFilesystem::Ntfs,
        crate::operations::FileSystem::ExFat => rdx_windows_native::HostFilesystem::ExFat,
        crate::operations::FileSystem::MacOs(_) | crate::operations::FileSystem::Linux(_) => {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::UnsupportedPlatform,
            ));
        }
    })
}

/// Maps a pre-dispatch Windows native error into shared host evidence.
#[cfg(windows)]
fn windows_host_not_attempted(
    error: rdx_windows_native::NativeError,
) -> crate::operations::PrimitiveFailure {
    crate::operations::PrimitiveFailure::not_attempted(map_windows_host_error(error))
}

/// Maps one closed Windows host mutation without losing dispatch certainty.
#[cfg(windows)]
fn map_windows_host_outcome(
    outcome: rdx_windows_native::HostOperationOutcome,
) -> Result<(), crate::operations::PrimitiveFailure> {
    use rdx_windows_native::HostOperationOutcome;

    match outcome {
        HostOperationOutcome::Succeeded => Ok(()),
        HostOperationOutcome::NotAttempted(error) => Err(
            crate::operations::PrimitiveFailure::not_attempted(map_windows_host_error(error)),
        ),
        HostOperationOutcome::CompletionUnknown(error) => Err(
            crate::operations::PrimitiveFailure::completion_unknown(map_windows_host_error(error)),
        ),
    }
}

/// Preserves collision and foreign-owner causes for drive-letter preferences.
#[cfg(windows)]
fn map_windows_drive_letter_outcome(
    outcome: rdx_windows_native::HostOperationOutcome,
    reset: bool,
) -> Result<(), crate::operations::PrimitiveFailure> {
    use crate::operations::{HostPrimitiveError, PrimitiveFailure};
    use rdx_windows_native::{HostOperationOutcome, NativeError};

    match outcome {
        HostOperationOutcome::Succeeded => Ok(()),
        HostOperationOutcome::NotAttempted(NativeError::Busy) if !reset => Err(
            PrimitiveFailure::not_attempted(HostPrimitiveError::DriveLetterInUse),
        ),
        HostOperationOutcome::NotAttempted(NativeError::InvalidRequest) if reset => Err(
            PrimitiveFailure::not_attempted(HostPrimitiveError::MappingNotOwned),
        ),
        other => map_windows_host_outcome(other),
    }
}

/// Maps sanitized Windows native errors into shared host causes.
#[cfg(windows)]
const fn map_windows_host_error(
    error: rdx_windows_native::NativeError,
) -> crate::operations::HostPrimitiveError {
    use crate::operations::HostPrimitiveError;
    use rdx_windows_native::NativeError;

    match error {
        NativeError::Busy => HostPrimitiveError::Busy,
        NativeError::ReadOnly => HostPrimitiveError::ReadOnly,
        NativeError::Cancelled => HostPrimitiveError::Cancelled,
        NativeError::TimedOut => HostPrimitiveError::TimedOut,
        NativeError::DeviceRemoved | NativeError::NoMedia => HostPrimitiveError::StaleBinding,
        NativeError::EvidenceIncomplete => HostPrimitiveError::UnsafeTopology,
        NativeError::UnsupportedPlatform => HostPrimitiveError::UnsupportedPlatform,
        NativeError::AccessDenied
        | NativeError::InvalidRequest
        | NativeError::EnumerationFailed
        | NativeError::ResourceLimit
        | NativeError::Other => HostPrimitiveError::Other,
    }
}
