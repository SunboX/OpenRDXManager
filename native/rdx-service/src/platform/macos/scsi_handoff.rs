// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact storage preparation before reacquiring disposable SCSI capture.

use crate::operations::HostVolumeFacts;
use rdx_macos_native::NativeError;

/// Retained native storage authority; callers never supply a disk path.
pub(super) trait CaptureAuthority {
    /// Reads fresh identity and mount state from the retained device.
    fn facts(&mut self) -> Result<HostVolumeFacts, NativeError>;
    /// Flushes and unmounts only this authority's exact volume tree.
    fn unmount(&mut self) -> Result<(), NativeError>;
    /// Invalidates the prepared mapping before parent authority is surrendered for capture.
    fn invalidate(&mut self);
}

/// Closes parent IOKit ownership before the retained factory can create an independent capture owner.
pub(super) fn release_parent_and_spawn<A, W>(
    parent: Option<A>,
    spawn: impl FnOnce() -> Result<W, NativeError>,
) -> Result<W, NativeError> {
    drop(parent);
    spawn()
}

/// Reuses a retained worker or performs the exact existing preparation/release/new-worker handoff.
pub(super) fn start_worker<A: CaptureAuthority, W>(
    authority: &mut Option<A>,
    worker: &mut Option<W>,
    cached: &mut Option<HostVolumeFacts>,
    format_unmounted: bool,
    spawn: impl FnOnce() -> Result<W, NativeError>,
) -> Result<(), NativeError> {
    if worker.is_some() {
        return Ok(());
    }
    if let Some(parent) = authority.as_mut() {
        *cached = Some(prepare_capture(parent, *cached, format_unmounted)?);
        parent.invalidate();
    }
    *worker = Some(release_parent_and_spawn(authority.take(), spawn)?);
    Ok(())
}

/// Preserves the pre-capture proof while preparing the exact storage handoff.
pub(super) fn prepare_capture(
    authority: &mut impl CaptureAuthority,
    previous: Option<HostVolumeFacts>,
    format_unmounted: bool,
) -> Result<HostVolumeFacts, NativeError> {
    let actual = authority.facts()?;
    let captured = capture_facts(previous, actual, format_unmounted)?;
    if actual.mounted {
        authority.unmount()?;
    }
    Ok(captured)
}

/// Keeps the format-owned mount transition separate from physical binding proof.
/// Actual facts are still returned to the host workflow; this snapshot is only
/// reused while exclusive SCSI capture temporarily hides storage from macOS.
pub(super) fn capture_facts(
    previous: Option<HostVolumeFacts>,
    actual: HostVolumeFacts,
    format_unmounted: bool,
) -> Result<HostVolumeFacts, NativeError> {
    let owned_unmount =
        previous.is_some_and(|expected| format_unmounted && expected.mounted && !actual.mounted);
    if let Some(expected) = previous {
        // Only the mount/filesystem view can disappear after our own unmount.
        // Physical medium, capacity, privilege and topology must still match.
        if expected.media_present != actual.media_present
            || expected.media_fingerprint != actual.media_fingerprint
            || expected.capacity_bytes != actual.capacity_bytes
            || expected.writable != actual.writable
            || expected.topology != actual.topology
            || (!owned_unmount
                && (expected.mounted != actual.mounted || expected.filesystem != actual.filesystem))
        {
            return Err(NativeError::DeviceRemoved);
        }
    }
    // Full SCSI revalidation still needs the pre-capture mount proof. The
    // subsequent native label read independently proves its exact remount.
    Ok(if owned_unmount {
        HostVolumeFacts {
            free_bytes: actual.free_bytes,
            ..previous.expect("owned unmount proof")
        }
    } else {
        actual
    })
}

#[cfg(target_os = "macos")]
impl CaptureAuthority for rdx_macos_native::MacDevice {
    /// Preserves the original second invalidation after exact storage preparation succeeds.
    fn invalidate(&mut self) {
        self.invalidate_media_mapping_for_rematch();
    }
    /// Refreshes the DA graph on the same USB authority before handoff.
    fn facts(&mut self) -> Result<HostVolumeFacts, NativeError> {
        self.invalidate_media_mapping_for_rematch();
        let mapping = self.pin_media()?;
        Ok(super::refresh::host_facts_from_mapping(&mapping))
    }

    /// Keeps ownership until exact native unmount has definitely succeeded.
    fn unmount(&mut self) -> Result<(), NativeError> {
        use rdx_macos_native::HostOperationOutcome;
        match self.pin_media()?.unmount(30_000) {
            HostOperationOutcome::Succeeded => Ok(()),
            HostOperationOutcome::NotAttempted(error)
            | HostOperationOutcome::DefinitelyRejected(error)
            | HostOperationOutcome::CompletionUnknown(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::{FileSystem, VolumeTopology};

    /// Models the OS boundary that refuses capture of mounted storage.
    struct Storage {
        facts: HostVolumeFacts,
        unmount_error: Option<NativeError>,
    }

    impl CaptureAuthority for Storage {
        /// Existing pure mount-state fixtures have no native mapping to invalidate.
        fn invalidate(&mut self) {}
        /// Supplies independently specified physical and host facts.
        fn facts(&mut self) -> Result<HostVolumeFacts, NativeError> {
            Ok(self.facts)
        }
        /// Models exact DA completion, including a busy mounted volume.
        fn unmount(&mut self) -> Result<(), NativeError> {
            if let Some(error) = self.unmount_error {
                return Err(error);
            }
            self.facts.mounted = false;
            self.facts.filesystem = None;
            Ok(())
        }
    }

    impl Storage {
        /// Models the capture prerequisite enforced by the native USB driver.
        fn capture(&self) -> Result<(), NativeError> {
            if self.facts.mounted {
                Err(NativeError::Busy)
            } else {
                Ok(())
            }
        }
    }

    /// Independent selected mounted cartridge proof.
    fn mounted() -> HostVolumeFacts {
        HostVolumeFacts {
            media_present: true,
            mounted: true,
            writable: true,
            free_bytes: 500,
            capacity_bytes: 1000,
            filesystem: Some(FileSystem::ExFat),
            media_fingerprint: Some([0xA5; 32]),
            topology: VolumeTopology::Simple,
        }
    }

    /// Catches reacquisition that drops DA ownership before flushing/unmounting.
    #[test]
    fn mounted_storage_is_prepared_before_scsi_reacquisition() {
        let expected = mounted();
        let mut storage = Storage {
            facts: expected,
            unmount_error: None,
        };
        assert_eq!(
            prepare_capture(&mut storage, Some(expected), false),
            Ok(expected)
        );
        assert_eq!(storage.capture(), Ok(()));
    }

    /// A failed unmount must stop handoff while the volume remains intact.
    #[test]
    fn busy_unmount_prevents_capture() {
        let expected = mounted();
        let mut storage = Storage {
            facts: expected,
            unmount_error: Some(NativeError::Busy),
        };
        assert_eq!(
            prepare_capture(&mut storage, Some(expected), false),
            Err(NativeError::Busy)
        );
        assert!(storage.facts.mounted);
    }

    /// Only a format-owned unmount may carry the prior mount proof across capture.
    #[test]
    fn only_owned_format_unmount_preserves_pre_capture_mount_proof() {
        let expected = mounted();
        let actual = HostVolumeFacts {
            mounted: false,
            filesystem: None,
            ..expected
        };
        let mut storage = Storage {
            facts: actual,
            unmount_error: None,
        };
        assert_eq!(
            prepare_capture(&mut storage, Some(expected), false),
            Err(NativeError::DeviceRemoved)
        );
        assert_eq!(
            prepare_capture(&mut storage, Some(expected), true),
            Ok(expected)
        );
    }

    /// Physical identity, capacity, permissions, and topology remain mandatory.
    #[test]
    fn owned_unmount_never_accepts_changed_media_or_host_authority() {
        let expected = mounted();
        for actual in [
            HostVolumeFacts {
                media_fingerprint: Some([0x5A; 32]),
                ..expected
            },
            HostVolumeFacts {
                capacity_bytes: 2000,
                ..expected
            },
            HostVolumeFacts {
                writable: false,
                ..expected
            },
            HostVolumeFacts {
                topology: VolumeTopology::Shared,
                ..expected
            },
            HostVolumeFacts {
                filesystem: Some(FileSystem::Ntfs),
                ..expected
            },
            HostVolumeFacts {
                media_present: false,
                ..expected
            },
        ] {
            let mut storage = Storage {
                facts: actual,
                unmount_error: None,
            };
            assert_eq!(
                prepare_capture(&mut storage, Some(expected), true),
                Err(NativeError::DeviceRemoved)
            );
            assert!(storage.facts.mounted);
        }
    }
}

#[cfg(test)]
#[path = "worker_lifecycle_tests.rs"]
mod lifecycle_tests;
