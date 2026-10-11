// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact mounted-volume label read across the SCSI-to-storage handoff.

use crate::operations::HostVolumeFacts;
use rdx_macos_native::NativeError;
use std::time::Instant;

/// Narrow retained-authority boundary; never opens a user-selected path.
pub(super) trait LabelAuthority {
    /// Reads fresh facts from the same retained native device.
    fn facts(&mut self) -> Result<HostVolumeFacts, NativeError>;
    /// Reads the label through that device's validated mounted descriptor.
    fn label(&mut self) -> Result<String, NativeError>;
}

/// Reads one label after handoff; errors remain fail-closed and path-free.
pub(super) fn read_remounted_label(
    authority: &mut impl LabelAuthority,
    expected: HostVolumeFacts,
    deadline: Instant,
    mut wait: impl FnMut(),
) -> Result<String, NativeError> {
    loop {
        match authority.facts() {
            Ok(facts) if facts.media_present && facts.mounted => {
                if !same_mounted_volume(expected, facts) {
                    return Err(NativeError::DeviceRemoved);
                }
                let label = authority.label()?;
                if !same_mounted_volume(expected, authority.facts()?) {
                    return Err(NativeError::DeviceRemoved);
                }
                return Ok(label);
            }
            Ok(_) => {}
            // DA can briefly return incomplete native state during remount.
            // Retrying never authorizes a read without a complete exact binding.
            Err(
                NativeError::DeviceRemoved
                | NativeError::EvidenceIncomplete
                | NativeError::EnumerationFailed
                | NativeError::Other,
            ) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(NativeError::EvidenceIncomplete);
        }
        wait();
    }
}

/// Checks every stable host binding field, excluding live filesystem accounting.
fn same_mounted_volume(expected: HostVolumeFacts, actual: HostVolumeFacts) -> bool {
    expected.media_present
        && expected.mounted
        && expected.media_fingerprint.is_some()
        && actual.media_present
        && actual.mounted
        && expected.media_fingerprint == actual.media_fingerprint
        && expected.capacity_bytes == actual.capacity_bytes
        && expected.writable == actual.writable
        && expected.filesystem == actual.filesystem
        && expected.topology == actual.topology
}

#[cfg(target_os = "macos")]
impl LabelAuthority for rdx_macos_native::MacDevice {
    /// Refreshes DA state on the same exact USB authority after each rematch observation.
    fn facts(&mut self) -> Result<HostVolumeFacts, NativeError> {
        self.invalidate_media_mapping_for_rematch();
        let mapping = self.pin_media()?;
        Ok(super::refresh::host_facts_from_mapping(&mapping))
    }
    /// Uses the retained, independently validated native mounted descriptor.
    fn label(&mut self) -> Result<String, NativeError> {
        self.volume_label()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::{FileSystem, VolumeTopology};
    use std::collections::VecDeque;
    use std::time::Duration;

    /// Models DA publication after a SCSI release, without any hardware writes.
    struct DelayedMount {
        observations: VecDeque<HostVolumeFacts>,
        mounted: bool,
        reads: usize,
        transient_error: Option<NativeError>,
    }

    impl LabelAuthority for DelayedMount {
        /// Publishes the next independently specified native observation.
        fn facts(&mut self) -> Result<HostVolumeFacts, NativeError> {
            if let Some(error) = self.transient_error.take() {
                return Err(error);
            }
            let facts = self.observations.pop_front().expect("bounded observations");
            self.mounted = facts.mounted;
            Ok(facts)
        }
        /// Mount-relative reads cannot succeed before DA publishes the mount.
        fn label(&mut self) -> Result<String, NativeError> {
            self.reads += 1;
            if self.mounted {
                Ok("OPENRDX".to_owned())
            } else {
                Err(NativeError::UnsupportedPlatform)
            }
        }
    }

    /// Independent exact mounted-cartridge facts.
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

    /// The handoff must wait for the selected volume before reading its label.
    #[test]
    fn label_read_waits_for_same_cartridge_to_remount() {
        let expected = mounted();
        let unmounted = HostVolumeFacts {
            mounted: false,
            free_bytes: 0,
            filesystem: None,
            ..expected
        };
        let mut authority = DelayedMount {
            observations: VecDeque::from([unmounted, expected, expected]),
            mounted: false,
            reads: 0,
            transient_error: None,
        };
        assert_eq!(
            read_remounted_label(
                &mut authority,
                expected,
                Instant::now() + Duration::from_secs(3),
                || {}
            ),
            Ok("OPENRDX".to_owned())
        );
        assert_eq!(authority.reads, 1);
    }

    /// A completed rematch identifying different media must never read its label.
    #[test]
    fn different_cartridge_rematch_is_rejected_before_label_read() {
        let expected = mounted();
        let swapped = HostVolumeFacts {
            media_fingerprint: Some([0x5A; 32]),
            ..expected
        };
        let mut authority = DelayedMount {
            observations: VecDeque::from([swapped]),
            mounted: true,
            reads: 0,
            transient_error: None,
        };
        assert_eq!(
            read_remounted_label(
                &mut authority,
                expected,
                Instant::now() + Duration::from_secs(3),
                || {}
            ),
            Err(NativeError::DeviceRemoved)
        );
        assert_eq!(authority.reads, 0);
    }

    /// An expired remount wait remains unavailable and cannot read an unmounted path.
    #[test]
    fn remount_deadline_fails_closed() {
        let expected = mounted();
        let unmounted = HostVolumeFacts {
            mounted: false,
            filesystem: None,
            ..expected
        };
        let mut authority = DelayedMount {
            observations: VecDeque::from([unmounted]),
            mounted: false,
            reads: 0,
            transient_error: None,
        };
        assert_eq!(
            read_remounted_label(&mut authority, expected, Instant::now(), || {}),
            Err(NativeError::EvidenceIncomplete)
        );
        assert_eq!(authority.reads, 0);
    }

    /// Changes to authorization-relevant host facts still fail before reading.
    #[test]
    fn changed_filesystem_capacity_privilege_or_topology_is_rejected() {
        let expected = mounted();
        for changed in [
            HostVolumeFacts {
                filesystem: Some(FileSystem::Ntfs),
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
                topology: VolumeTopology::BootOrSystem,
                ..expected
            },
        ] {
            let mut authority = DelayedMount {
                observations: VecDeque::from([changed]),
                mounted: true,
                reads: 0,
                transient_error: None,
            };
            assert_eq!(
                read_remounted_label(
                    &mut authority,
                    expected,
                    Instant::now() + Duration::from_secs(3),
                    || {}
                ),
                Err(NativeError::DeviceRemoved)
            );
            assert_eq!(authority.reads, 0);
        }
    }

    /// A swap between read and readback cannot authorize a confirmation.
    #[test]
    fn cartridge_swap_during_label_read_is_rejected() {
        let expected = mounted();
        let swapped = HostVolumeFacts {
            media_fingerprint: Some([0x5A; 32]),
            ..expected
        };
        let mut authority = DelayedMount {
            observations: VecDeque::from([expected, swapped]),
            mounted: true,
            reads: 0,
            transient_error: None,
        };
        assert_eq!(
            read_remounted_label(
                &mut authority,
                expected,
                Instant::now() + Duration::from_secs(3),
                || {}
            ),
            Err(NativeError::DeviceRemoved)
        );
    }

    /// Filesystem accounting may change while exact storage identity remains valid.
    #[test]
    fn free_space_changes_do_not_invalidate_the_label_read() {
        let expected = mounted();
        let accounting = HostVolumeFacts {
            free_bytes: 450,
            ..expected
        };
        let mut authority = DelayedMount {
            observations: VecDeque::from([expected, accounting]),
            mounted: true,
            reads: 0,
            transient_error: None,
        };
        assert_eq!(
            read_remounted_label(
                &mut authority,
                expected,
                Instant::now() + Duration::from_secs(3),
                || {}
            ),
            Ok("OPENRDX".to_owned())
        );
    }
    /// A transient native rematch error must not be treated as missing rename support.
    #[test]
    fn transient_native_rematch_error_waits_for_valid_identity() {
        let expected = mounted();
        let mut authority = DelayedMount {
            observations: VecDeque::from([expected, expected]),
            mounted: false,
            reads: 0,
            transient_error: Some(NativeError::Other),
        };
        let mut waits = 0;
        assert_eq!(
            read_remounted_label(
                &mut authority,
                expected,
                Instant::now() + Duration::from_secs(3),
                || {
                    waits += 1;
                }
            ),
            Ok("OPENRDX".to_owned())
        );
        assert_eq!(waits, 1);
        assert_eq!(authority.reads, 1);
    }
}
