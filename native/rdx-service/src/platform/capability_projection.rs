// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Projects validated receiver and host facts into renderer-safe operation capabilities.

use super::*;

/// Builds a conservative sparse operation map from device and host evidence.
pub(super) fn device_capabilities(
    drive_mode_supported: bool,
    interface: DeviceInterface,
    platform: PlatformCapabilities,
    host_facts: Option<HostVolumeFacts>,
    sata_mode_reported: bool,
    volume_label_available: bool,
) -> BTreeMap<OperationKind, Capability> {
    let available = || Capability {
        state: CapabilityState::Available,
        reason: None,
    };
    let unavailable = |state, reason| Capability {
        state,
        reason: Some(ReasonCode::new(reason).expect("static capability reason is valid")),
    };
    let mut capabilities = BTreeMap::from([
        (OperationKind::StatusRefresh, available()),
        (OperationKind::SelfTest, available()),
        (OperationKind::LedTest, available()),
    ]);
    let media_present = host_facts.is_some_and(|facts| facts.media_present);
    let media_ejected = host_facts.is_some_and(|facts| !facts.media_present);
    capabilities.insert(
        OperationKind::FirmwareUpdate,
        if interface == DeviceInterface::Legacy {
            unavailable(
                CapabilityState::EvidenceIncomplete,
                "legacy-bip-format-unproven",
            )
        } else if !media_ejected {
            unavailable(
                CapabilityState::WrongMediaState,
                if media_present {
                    "media-must-be-ejected"
                } else {
                    "media-state-unavailable"
                },
            )
        } else {
            available()
        },
    );
    capabilities.insert(
        OperationKind::DriveModeSet,
        if !drive_mode_supported {
            unavailable(
                CapabilityState::UnsupportedProduct,
                "drive-mode-not-supported",
            )
        } else if !media_ejected {
            unavailable(
                CapabilityState::WrongMediaState,
                if media_present {
                    "media-must-be-ejected"
                } else {
                    "media-state-unavailable"
                },
            )
        } else {
            available()
        },
    );
    capabilities.insert(
        OperationKind::SataModeSet,
        if interface != DeviceInterface::Sata3 {
            unavailable(
                CapabilityState::UnsupportedProduct,
                "sata-mode-not-supported",
            )
        } else if !sata_mode_reported {
            unavailable(
                CapabilityState::EvidenceIncomplete,
                "current-sata-mode-unavailable",
            )
        } else if !media_ejected {
            unavailable(
                CapabilityState::WrongMediaState,
                if media_present {
                    "media-must-be-ejected"
                } else {
                    "media-state-unavailable"
                },
            )
        } else {
            available()
        },
    );
    capabilities.insert(
        OperationKind::EjectSafe,
        if platform.safe_eject {
            if media_present {
                available()
            } else {
                unavailable(CapabilityState::WrongMediaState, "media-required")
            }
        } else {
            unavailable(
                CapabilityState::UnsupportedPlatform,
                "safe-eject-unavailable",
            )
        },
    );
    capabilities.insert(
        OperationKind::EjectForce,
        if platform.force_eject {
            if media_present {
                available()
            } else {
                unavailable(CapabilityState::WrongMediaState, "media-required")
            }
        } else {
            unavailable(
                CapabilityState::UnsupportedPlatform,
                "force-eject-unavailable",
            )
        },
    );
    capabilities.insert(
        OperationKind::VolumeLabelSet,
        if platform.privileged && volume_label_available {
            match host_facts {
                Some(facts)
                    if matches!(
                        facts.filesystem,
                        Some(crate::operations::FileSystem::Linux(
                            crate::model::Filesystem::F2fs
                        ))
                    ) || (cfg!(target_os = "linux")
                        && matches!(
                            facts.filesystem,
                            Some(crate::operations::FileSystem::MacOs(
                                crate::model::Filesystem::Fat16 | crate::model::Filesystem::Fat32
                            ))
                        )) =>
                {
                    unavailable(CapabilityState::UnsupportedPlatform, "unsupported-platform")
                }
                Some(facts)
                    if facts.media_present
                        && facts.mounted
                        && facts.writable
                        && matches!(
                            facts.filesystem,
                            Some(
                                crate::operations::FileSystem::Ntfs
                                    | crate::operations::FileSystem::ExFat
                                    | crate::operations::FileSystem::MacOs(_)
                                    | crate::operations::FileSystem::Linux(
                                        crate::model::Filesystem::Ext2
                                            | crate::model::Filesystem::Ext3
                                            | crate::model::Filesystem::Ext4
                                            | crate::model::Filesystem::Xfs
                                            | crate::model::Filesystem::Btrfs
                                    )
                            )
                        )
                        && facts.topology == crate::operations::VolumeTopology::Simple =>
                {
                    available()
                }
                _ => unavailable(CapabilityState::WrongMediaState, "volume-not-mounted"),
            }
        } else {
            unavailable(CapabilityState::UnsupportedPlatform, "unsupported-platform")
        },
    );
    capabilities.insert(
        OperationKind::Format,
        if platform.format {
            if media_present {
                available()
            } else {
                unavailable(CapabilityState::WrongMediaState, "media-required")
            }
        } else {
            unavailable(CapabilityState::UnsupportedPlatform, "format-unavailable")
        },
    );
    capabilities.insert(
        OperationKind::WriteReadTest,
        if platform.write_read_available() {
            if media_present {
                available()
            } else {
                unavailable(CapabilityState::WrongMediaState, "media-required")
            }
        } else {
            unavailable(
                CapabilityState::UnsupportedPlatform,
                "write-read-unavailable",
            )
        },
    );
    let drive_letter = if platform.drive_letter && interface == DeviceInterface::Usb3 {
        if media_present {
            unavailable(CapabilityState::WrongMediaState, "media-must-be-ejected")
        } else {
            available()
        }
    } else if !platform.drive_letter {
        unavailable(
            CapabilityState::UnsupportedPlatform,
            "drive-letter-unavailable",
        )
    } else {
        unavailable(
            CapabilityState::UnsupportedProduct,
            "drive-letter-not-supported",
        )
    };
    capabilities.insert(OperationKind::DriveLetterSet, drive_letter.clone());
    capabilities.insert(OperationKind::DriveLetterReset, drive_letter);
    capabilities
}

#[cfg(test)]
mod label_tests {
    use super::*;
    use crate::operations::{FileSystem, HostVolumeFacts, VolumeTopology};

    #[test]
    fn label_readiness_is_independent_of_windows_drive_letters() {
        let facts = HostVolumeFacts {
            media_present: true,
            writable: true,
            mounted: true,
            free_bytes: 10,
            capacity_bytes: 100,
            filesystem: Some(FileSystem::ExFat),
            media_fingerprint: Some([1; 32]),
            topology: VolumeTopology::Simple,
        };
        for drive_letter in [true, false] {
            let platform = PlatformCapabilities::try_new(
                true,
                true,
                true,
                true,
                true,
                true,
                drive_letter,
                false,
            )
            .unwrap();
            for filesystem in [
                FileSystem::Ntfs,
                FileSystem::ExFat,
                FileSystem::MacOs(crate::model::Filesystem::Apfs),
                FileSystem::Linux(crate::model::Filesystem::Ext2),
                FileSystem::Linux(crate::model::Filesystem::Ext3),
                FileSystem::Linux(crate::model::Filesystem::Ext4),
                FileSystem::Linux(crate::model::Filesystem::Xfs),
                FileSystem::Linux(crate::model::Filesystem::Btrfs),
            ] {
                let mut facts = facts;
                facts.filesystem = Some(filesystem);
                assert_eq!(
                    device_capabilities(
                        true,
                        DeviceInterface::Usb3,
                        platform,
                        Some(facts),
                        false,
                        true
                    )[&OperationKind::VolumeLabelSet]
                        .state,
                    CapabilityState::Available
                );
                assert_ne!(
                    device_capabilities(
                        true,
                        DeviceInterface::Usb3,
                        platform,
                        Some(facts),
                        false,
                        false
                    )[&OperationKind::VolumeLabelSet]
                        .state,
                    CapabilityState::Available
                );
                for unavailable in [
                    HostVolumeFacts {
                        writable: false,
                        ..facts
                    },
                    HostVolumeFacts {
                        mounted: false,
                        ..facts
                    },
                    HostVolumeFacts {
                        topology: VolumeTopology::Shared,
                        ..facts
                    },
                ] {
                    assert_ne!(
                        device_capabilities(
                            true,
                            DeviceInterface::Usb3,
                            platform,
                            Some(unavailable),
                            false,
                            true
                        )[&OperationKind::VolumeLabelSet]
                            .state,
                        CapabilityState::Available
                    );
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_label_support {
    use super::*;
    /// Reading a known label must not advertise unsupported mounted rename operations.
    #[test]
    fn unsupported_mounted_label_mutations_remain_unavailable() {
        let platform =
            PlatformCapabilities::try_new(true, true, true, true, true, true, false, false)
                .unwrap();
        for filesystem in [
            crate::operations::FileSystem::Linux(crate::model::Filesystem::F2fs),
            crate::operations::FileSystem::MacOs(crate::model::Filesystem::Fat16),
            crate::operations::FileSystem::MacOs(crate::model::Filesystem::Fat32),
        ] {
            let facts = crate::operations::HostVolumeFacts {
                media_present: true,
                writable: true,
                mounted: true,
                free_bytes: 10,
                capacity_bytes: 100,
                filesystem: Some(filesystem),
                media_fingerprint: Some([1; 32]),
                topology: crate::operations::VolumeTopology::Simple,
            };
            assert_eq!(
                device_capabilities(
                    true,
                    DeviceInterface::Usb3,
                    platform,
                    Some(facts),
                    false,
                    true
                )[&OperationKind::VolumeLabelSet]
                    .state,
                CapabilityState::UnsupportedPlatform
            );
        }
    }
}
