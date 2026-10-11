// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Non-disruptive macOS candidate and cartridge refresh helpers.

use crate::operations::{FileSystem, HostVolumeFacts, VolumeTopology};
use crate::platform::{PlatformError, media_fingerprint};

use super::{PendingCandidateAuthority, map_native_platform_error};

/// Decision for one freshly rematched cartridge-media generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SafeEjectRematchState {
    /// The dock is present but its prior cartridge hierarchy is not complete yet.
    Waiting,
    /// The complete rematched hierarchy proves the same cartridge identity.
    Ready,
    /// A complete rematched hierarchy identifies a different cartridge.
    Stale,
}

/// Decision for one fresh exact-device observation after eject dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SafeEjectDepartureReadbackState {
    /// Two consecutive fresh observations prove the cartridge hierarchy absent.
    Departed,
    /// The storage stack still reports media or has not completed its transition.
    Waiting,
    /// A non-transient native failure prevents authoritative departure evidence.
    Failed(rdx_macos_native::NativeError),
}

/// Tracks fresh no-media evidence across bounded Safe Eject readback polls.
#[derive(Default)]
pub(super) struct SafeEjectDepartureConfirmation {
    prior_no_media: bool,
}

impl SafeEjectDepartureConfirmation {
    /// Accepts departure only after two consecutive fresh no-media observations.
    pub(super) fn observe(
        &mut self,
        observation: Result<bool, rdx_macos_native::NativeError>,
    ) -> SafeEjectDepartureReadbackState {
        match observation {
            Ok(false) if self.prior_no_media => SafeEjectDepartureReadbackState::Departed,
            Ok(false) => {
                self.prior_no_media = true;
                SafeEjectDepartureReadbackState::Waiting
            }
            Ok(true)
            | Err(rdx_macos_native::NativeError::DeviceRemoved)
            | Err(rdx_macos_native::NativeError::EnumerationFailed)
            | Err(rdx_macos_native::NativeError::EvidenceIncomplete)
            | Err(rdx_macos_native::NativeError::Other) => {
                self.prior_no_media = false;
                SafeEjectDepartureReadbackState::Waiting
            }
            Err(error) => {
                self.prior_no_media = false;
                SafeEjectDepartureReadbackState::Failed(error)
            }
        }
    }
}

/// Classifies one path-free media observation before Safe Eject mutates it.
pub(super) fn safe_eject_rematch_state(
    expected_fingerprint: [u8; 32],
    whole_media_present: bool,
    media_count: usize,
    observed_fingerprint: Option<[u8; 32]>,
) -> SafeEjectRematchState {
    if !whole_media_present || media_count == 0 {
        SafeEjectRematchState::Waiting
    } else if matches!(observed_fingerprint, Some(observed) if observed == expected_fingerprint) {
        SafeEjectRematchState::Ready
    } else {
        SafeEjectRematchState::Stale
    }
}

/// Returns whether one native failure can represent an incomplete rematch generation.
pub(super) const fn transient_storage_rematch_error(error: rdx_macos_native::NativeError) -> bool {
    matches!(
        error,
        rdx_macos_native::NativeError::DeviceRemoved
            | rdx_macos_native::NativeError::EnumerationFailed
            | rdx_macos_native::NativeError::EvidenceIncomplete
            | rdx_macos_native::NativeError::Other
    )
}

/// Returns whether an initial mapping is complete or proves no cartridge media.
pub(super) const fn initial_mapping_complete(
    whole_media_present: bool,
    media_count: usize,
) -> bool {
    !whole_media_present || media_count > 0
}

/// Returns whether a rematched generation contains the prior partition identity.
const fn rematch_mapping_complete(
    wait_for_partitioned_media: bool,
    wait_for_mounted_media: bool,
    whole_media_present: bool,
    media_count: usize,
    mounted_media_count: usize,
) -> bool {
    !wait_for_partitioned_media
        || (whole_media_present
            && media_count > 0
            && (!wait_for_mounted_media || mounted_media_count > 0))
}

/// Returns whether a mounted `0 bytes free` sample must be observed once more.
///
/// Disk Arbitration can briefly expose a valid mounted identity while the
/// filesystem accounting layer reports zero available blocks. Publishing that
/// single sample would render an almost-empty cartridge as completely full.
/// A previously established zero remains authoritative, and two identical
/// fresh samples still allow a genuinely full cartridge to be reported.
pub(super) fn capacity_refresh_requires_confirmation(
    previous: Option<HostVolumeFacts>,
    current: HostVolumeFacts,
    confirming_sample: Option<HostVolumeFacts>,
) -> bool {
    if !current.media_present
        || !current.mounted
        || current.capacity_bytes == 0
        || current.free_bytes != 0
        || confirming_sample == Some(current)
    {
        return false;
    }
    !previous.is_some_and(|facts| {
        facts.media_fingerprint == current.media_fingerprint
            && facts.capacity_bytes == current.capacity_bytes
            && facts.mounted
            && facts.free_bytes == 0
    })
}

/// Retries a transient incomplete IOKit generation after prior USB capture.
pub(super) fn enumerate_after_storage_rematch(
    pending: &PendingCandidateAuthority<rdx_macos_native::MacCandidate>,
) -> Result<Vec<rdx_macos_native::MacCandidate>, PlatformError> {
    let expected_candidates = pending.len();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let candidates =
            rdx_macos_native::enumerate_candidates().map_err(map_native_platform_error)?;
        if candidates.len() >= expected_candidates
            || expected_candidates == 0
            || std::time::Instant::now() >= deadline
        {
            return Ok(candidates);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Maps one exact pinned Disk Arbitration set into path-free host facts.
pub(super) fn host_facts_from_mapping(
    mapping: &rdx_macos_native::MediaLeaseSet<'_>,
) -> HostVolumeFacts {
    let (writable, free_bytes, capacity_bytes) = mapping.volume_facts();
    let media_fingerprint = mapping.whole_media_present().then(|| {
        media_fingerprint(
            b"macos-da-iokit-v1",
            capacity_bytes,
            writable,
            mapping.identity_material(),
        )
    });
    HostVolumeFacts {
        media_present: mapping.whole_media_present(),
        writable,
        mounted: mapping.mounted_media_count() > 0,
        free_bytes,
        capacity_bytes,
        filesystem: mapping
            .mounted_filesystem()
            .map(|filesystem| match filesystem {
                rdx_macos_native::MountedFilesystem::ExFat => FileSystem::ExFat,
                rdx_macos_native::MountedFilesystem::MacOs(selector) => {
                    crate::operations::FileSystem::MacOs(match selector {
                        3 => crate::model::Filesystem::Fat,
                        7 => crate::model::Filesystem::Hfs,
                        _ => crate::model::Filesystem::Apfs,
                    })
                }
                rdx_macos_native::MountedFilesystem::Ntfs => FileSystem::Ntfs,
            }),
        media_fingerprint,
        topology: if mapping.mutation_topology_safe() {
            VolumeTopology::Simple
        } else {
            VolumeTopology::BootOrSystem
        },
    }
}

/// Waits briefly for storage-stack rematch after the preceding exclusive probe.
pub(super) fn refresh_host_facts_without_transport(
    candidate: &rdx_macos_native::MacCandidate,
    previous_facts: Option<HostVolumeFacts>,
) -> Result<HostVolumeFacts, PlatformError> {
    let wait_for_rematch = previous_facts.is_some_and(|facts| facts.media_present);
    let wait_for_mount = previous_facts.is_some_and(|facts| facts.mounted);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut pending_capacity_confirmation = None;
    loop {
        let mut authority = match rdx_macos_native::MacDevice::open(candidate) {
            Ok(authority) => authority,
            Err(error)
                if wait_for_rematch
                    && std::time::Instant::now() < deadline
                    && transient_storage_rematch_error(error) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(map_native_platform_error(error)),
        };
        let (facts, mapping_complete) = {
            let mapping = match authority.pin_media() {
                Ok(mapping) => mapping,
                Err(error)
                    if wait_for_rematch
                        && std::time::Instant::now() < deadline
                        && transient_storage_rematch_error(error) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                Err(error) => return Err(map_native_platform_error(error)),
            };
            let mapping_complete = rematch_mapping_complete(
                wait_for_rematch,
                wait_for_mount,
                mapping.whole_media_present(),
                mapping.media_count(),
                mapping.mounted_media_count(),
            );
            (host_facts_from_mapping(&mapping), mapping_complete)
        };
        let capacity_confirmation_required = capacity_refresh_requires_confirmation(
            previous_facts,
            facts,
            pending_capacity_confirmation,
        );
        if mapping_complete && !capacity_confirmation_required {
            return Ok(facts);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(if capacity_confirmation_required {
                previous_facts.unwrap_or(facts)
            } else {
                facts
            });
        }
        pending_capacity_confirmation = capacity_confirmation_required.then_some(facts);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SafeEjectDepartureConfirmation, SafeEjectDepartureReadbackState, SafeEjectRematchState,
        capacity_refresh_requires_confirmation, initial_mapping_complete, rematch_mapping_complete,
        safe_eject_rematch_state, transient_storage_rematch_error,
    };
    use crate::operations::{FileSystem, HostVolumeFacts, VolumeTopology};

    /// Builds one mounted cartridge fact set for capacity-transition tests.
    fn mounted_facts(free_bytes: u64) -> HostVolumeFacts {
        HostVolumeFacts {
            media_present: true,
            writable: true,
            mounted: true,
            free_bytes,
            capacity_bytes: 320_067_338_240,
            filesystem: Some(FileSystem::Ntfs),
            topology: VolumeTopology::Simple,
            media_fingerprint: Some([0xA5; 32]),
        }
    }

    #[test]
    fn only_incomplete_rematch_generations_are_retried() {
        use rdx_macos_native::NativeError;

        for error in [
            NativeError::DeviceRemoved,
            NativeError::EnumerationFailed,
            NativeError::EvidenceIncomplete,
            NativeError::Other,
        ] {
            assert!(transient_storage_rematch_error(error));
        }
        for error in [
            NativeError::UnsupportedPlatform,
            NativeError::InvalidRequest,
            NativeError::TransportUnavailable,
            NativeError::AccessDenied,
            NativeError::Busy,
            NativeError::TimedOut,
            NativeError::ResourceLimit,
        ] {
            assert!(!transient_storage_rematch_error(error));
        }
    }

    #[test]
    fn prior_partitioned_media_waits_for_its_child_identity() {
        assert!(!rematch_mapping_complete(true, true, false, 0, 0));
        assert!(!rematch_mapping_complete(true, true, true, 0, 0));
        assert!(!rematch_mapping_complete(true, true, true, 1, 0));
        assert!(rematch_mapping_complete(true, true, true, 1, 1));
        assert!(rematch_mapping_complete(true, false, true, 1, 0));
        assert!(rematch_mapping_complete(false, false, true, 0, 0));
    }

    #[test]
    fn safe_eject_waits_for_complete_same_cartridge_rematch() {
        let expected = [0xA5; 32];

        assert_eq!(
            safe_eject_rematch_state(expected, false, 0, None),
            SafeEjectRematchState::Waiting,
        );
        assert_eq!(
            safe_eject_rematch_state(expected, true, 0, Some(expected)),
            SafeEjectRematchState::Waiting,
        );
        assert_eq!(
            safe_eject_rematch_state(expected, true, 1, Some(expected)),
            SafeEjectRematchState::Ready,
        );
        assert_eq!(
            safe_eject_rematch_state(expected, true, 1, Some([0x5A; 32])),
            SafeEjectRematchState::Stale,
        );
    }

    #[test]
    fn safe_eject_readback_waits_through_transient_storage_departure() {
        use rdx_macos_native::NativeError;

        for error in [
            NativeError::DeviceRemoved,
            NativeError::EnumerationFailed,
            NativeError::EvidenceIncomplete,
            NativeError::Other,
        ] {
            let mut confirmation = SafeEjectDepartureConfirmation::default();
            assert_eq!(
                confirmation.observe(Err(error)),
                SafeEjectDepartureReadbackState::Waiting,
            );
        }
        for error in [
            NativeError::UnsupportedPlatform,
            NativeError::InvalidRequest,
            NativeError::TransportUnavailable,
            NativeError::AccessDenied,
            NativeError::Busy,
            NativeError::TimedOut,
            NativeError::ResourceLimit,
        ] {
            let mut confirmation = SafeEjectDepartureConfirmation::default();
            assert_eq!(
                confirmation.observe(Err(error)),
                SafeEjectDepartureReadbackState::Failed(error),
            );
        }
    }

    #[test]
    fn safe_eject_requires_two_consecutive_same_dock_no_media_observations() {
        use rdx_macos_native::NativeError;

        let mut confirmation = SafeEjectDepartureConfirmation::default();
        assert_eq!(
            confirmation.observe(Ok(false)),
            SafeEjectDepartureReadbackState::Waiting,
        );
        assert_eq!(
            confirmation.observe(Ok(true)),
            SafeEjectDepartureReadbackState::Waiting,
        );
        assert_eq!(
            confirmation.observe(Ok(false)),
            SafeEjectDepartureReadbackState::Waiting,
        );
        assert_eq!(
            confirmation.observe(Err(NativeError::DeviceRemoved)),
            SafeEjectDepartureReadbackState::Waiting,
        );
        assert_eq!(
            confirmation.observe(Ok(false)),
            SafeEjectDepartureReadbackState::Waiting,
        );
        assert_eq!(
            confirmation.observe(Ok(false)),
            SafeEjectDepartureReadbackState::Departed,
        );
    }

    #[test]
    fn initial_mapping_waits_only_for_a_present_whole_disks_child_identity() {
        assert!(initial_mapping_complete(false, 0));
        assert!(!initial_mapping_complete(true, 0));
        assert!(initial_mapping_complete(true, 1));
    }

    #[test]
    fn sudden_zero_free_space_requires_one_confirming_sample() {
        let previous = mounted_facts(319_960_000_000);
        let zero_free = mounted_facts(0);
        let ordinary_change = mounted_facts(319_900_000_000);

        assert!(capacity_refresh_requires_confirmation(
            Some(previous),
            zero_free,
            None,
        ));
        assert!(capacity_refresh_requires_confirmation(
            None, zero_free, None
        ));
        assert!(!capacity_refresh_requires_confirmation(
            Some(previous),
            zero_free,
            Some(zero_free),
        ));
        assert!(!capacity_refresh_requires_confirmation(
            Some(zero_free),
            zero_free,
            None,
        ));
        assert!(!capacity_refresh_requires_confirmation(
            Some(previous),
            ordinary_change,
            None,
        ));
    }
}
