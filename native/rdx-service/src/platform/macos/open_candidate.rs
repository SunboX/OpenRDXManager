// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Existing exact-candidate registry, media mapping and worker acquisition path.

use super::*;
use crate::platform::DiscoveryFailure;

impl MacOsBackend {
    /// Reopens one generation recipe and revalidates the exact registry service.
    pub(super) fn open_registry_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        self.last_open_failure = None;
        if !self.native_active {
            self.last_open_failure = Some(DiscoveryFailure::RegistryOpen);
            return Err(PlatformError::TransportUnavailable);
        }
        #[cfg(target_os = "macos")]
        {
            let staged = self
                .staged
                .as_ref()
                .and_then(|recipes| recipes.reopen(&candidate.locator));
            let probing_staged_candidate = staged.is_some();
            let mut prefilter_rejected = false;
            let mut failure_stage = DiscoveryFailure::RegistryRecipe;
            let opened = (|| {
                let retained = staged
                    .or_else(|| self.pending.reopen(&candidate.locator))
                    .ok_or(PlatformError::DeviceRemoved)?;
                if retained.token() != candidate.token() {
                    return Err(PlatformError::DeviceRemoved);
                }
                if !retained.matches_rdx_identity_hint() {
                    failure_stage = DiscoveryFailure::Prefilter;
                    prefilter_rejected = true;
                    return Err(PlatformError::DeviceUnavailable);
                }
                failure_stage = DiscoveryFailure::RegistryOpen;
                let mut authority = rdx_macos_native::MacDevice::open(retained)
                    .map_err(map_native_platform_error)?;
                let rematch_identity = retained.rematch_identity();
                let cached_host_facts = {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                    let mut pending_capacity_confirmation = None;
                    loop {
                        failure_stage = DiscoveryFailure::MediaMap;
                        let mut mapping = match authority.pin_media() {
                            Ok(mapping) => mapping,
                            Err(error)
                                if std::time::Instant::now() < deadline
                                    && transient_storage_rematch_error(error) =>
                            {
                                std::thread::sleep(std::time::Duration::from_millis(100));
                                continue;
                            }
                            Err(error) => return Err(map_native_platform_error(error)),
                        };
                        if !initial_mapping_complete(
                            mapping.whole_media_present(),
                            mapping.media_count(),
                        ) && std::time::Instant::now() < deadline
                        {
                            drop(mapping);
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            continue;
                        }
                        let facts = host_facts_from_mapping(&mapping);
                        if capacity_refresh_requires_confirmation(
                            None,
                            facts,
                            pending_capacity_confirmation,
                        ) && std::time::Instant::now() < deadline
                        {
                            pending_capacity_confirmation = Some(facts);
                            drop(mapping);
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            continue;
                        }
                        if mapping.mounted_media_count() > 0 {
                            failure_stage = DiscoveryFailure::Unmount;
                            match mapping.unmount(30_000) {
                                rdx_macos_native::HostOperationOutcome::Succeeded => {}
                                rdx_macos_native::HostOperationOutcome::NotAttempted(error)
                                | rdx_macos_native::HostOperationOutcome::DefinitelyRejected(
                                    error,
                                )
                                | rdx_macos_native::HostOperationOutcome::CompletionUnknown(
                                    error,
                                ) => {
                                    // An ambiguous DA failure does not prove device removal.
                                    return Err(map_native_platform_error(error));
                                }
                            }
                        }
                        break facts;
                    }
                };
                authority.invalidate_media_mapping_for_rematch();
                drop(authority);
                failure_stage = DiscoveryFailure::WorkerAcquisition;
                let scsi = rdx_macos_native::MacScsiWorkerLease::spawn(&rematch_identity).map_err(
                    |error| {
                        if let Some(diagnostic) =
                            rdx_macos_native::take_last_worker_startup_failure()
                        {
                            failure_stage = DiscoveryFailure::WorkerStartup(diagnostic);
                        }
                        // Diagnostic evidence never changes the original native result or Busy policy.
                        map_native_platform_error(error)
                    },
                )?;
                Ok(CandidateLease::new(MacOsDeviceHandle {
                    _authority: None,
                    rematch_identity,
                    scsi: Some(scsi),
                    cached_host_facts: Some(cached_host_facts),
                    storage_unmounted_for_format: false,
                    safe_eject_dispatched: false,
                    pending_format: None,
                    format_passphrase: None,
                    combined_format_complete: false,
                }))
            })();
            if opened.is_err() {
                self.last_open_failure = Some(failure_stage);
            }
            if probing_staged_candidate {
                if prefilter_rejected {
                    self.record_staged_prefilter_rejection(candidate.token());
                } else {
                    self.record_staged_candidate_outcome(
                        candidate.token(),
                        opened.as_ref().err().copied(),
                    );
                }
            }
            opened
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = candidate;
            Err(PlatformError::TransportUnavailable)
        }
    }
}
