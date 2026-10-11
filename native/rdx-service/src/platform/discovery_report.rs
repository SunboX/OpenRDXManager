// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Path-free diagnostics for one complete native discovery pass.

use std::collections::BTreeMap;

use serde::ser::{Serialize, SerializeSeq, SerializeStruct, Serializer};

use crate::model::{DeviceId, DeviceSnapshot};

use super::{
    CandidateLease, DeviceRegistry, PlatformBackend, PlatformError, ValidatedCandidate,
    metadata_is_sane, reject_duplicate_candidates, revalidate_candidate_lease,
};

/// Aggregated candidate outcomes safe to publish outside the native boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryDiagnostics {
    candidate_count: usize,
    accepted_count: usize,
    rejections: Vec<(&'static str, usize)>,
}

impl DiscoveryDiagnostics {
    /// Creates diagnostics for a pass where every candidate was accepted.
    #[must_use]
    pub fn accepted(candidate_count: usize) -> Self {
        Self {
            candidate_count,
            accepted_count: candidate_count,
            rejections: Vec::new(),
        }
    }

    /// Creates a bounded aggregate from validated and rejected candidate counts.
    pub(super) fn new(
        candidate_count: usize,
        accepted_count: usize,
        rejections: Vec<(&'static str, usize)>,
    ) -> Self {
        debug_assert_eq!(
            candidate_count,
            accepted_count + rejections.iter().map(|(_, count)| count).sum::<usize>()
        );
        Self {
            candidate_count,
            accepted_count,
            rejections,
        }
    }

    /// Returns the number of enumerated candidates before candidate-local validation.
    #[must_use]
    pub const fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    /// Returns the number of candidates admitted to the authoritative snapshot.
    #[must_use]
    pub const fn accepted_count(&self) -> usize {
        self.accepted_count
    }

    /// Returns stable aggregate reasons without tokens, locators, or native text.
    #[must_use]
    pub fn rejections(&self) -> &[(&'static str, usize)] {
        &self.rejections
    }
}

impl Serialize for DiscoveryDiagnostics {
    /// Serializes only bounded counts and stable reason codes.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serializer.serialize_struct("DiscoveryDiagnostics", 3)?;
        object.serialize_field("candidateCount", &self.candidate_count)?;
        object.serialize_field("acceptedCount", &self.accepted_count)?;
        object.serialize_field("rejections", &Rejections(&self.rejections))?;
        object.end()
    }
}

/// Serializer adapter that emits named fields instead of tuple arrays.
struct Rejections<'report>(&'report [(&'static str, usize)]);

impl Serialize for Rejections<'_> {
    /// Serializes each aggregate as `{reason, count}`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (reason, count) in self.0 {
            sequence.serialize_element(&Rejection { reason, count })?;
        }
        sequence.end()
    }
}

/// One transient aggregate value used only during serialization.
#[derive(serde::Serialize)]
struct Rejection<'reason> {
    reason: &'reason str,
    count: &'reason usize,
}

/// Full authoritative device snapshot plus its candidate-level diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDiscoveryReport {
    snapshots: Vec<DeviceSnapshot>,
    diagnostics: DiscoveryDiagnostics,
}

impl ValidatedDiscoveryReport {
    /// Creates a report for a backend with no candidate-local rejection detail.
    #[must_use]
    pub fn all_accepted(snapshots: Vec<DeviceSnapshot>) -> Self {
        let diagnostics = DiscoveryDiagnostics::accepted(snapshots.len());
        Self::new(snapshots, diagnostics)
    }

    /// Creates one internally consistent report.
    pub(super) fn new(snapshots: Vec<DeviceSnapshot>, diagnostics: DiscoveryDiagnostics) -> Self {
        debug_assert_eq!(snapshots.len(), diagnostics.accepted_count());
        Self {
            snapshots,
            diagnostics,
        }
    }

    /// Returns the authoritative path-free device list.
    #[must_use]
    pub fn snapshots(&self) -> &[DeviceSnapshot] {
        &self.snapshots
    }

    /// Consumes this report and returns its authoritative device list.
    #[must_use]
    pub fn into_snapshots(self) -> Vec<DeviceSnapshot> {
        self.snapshots
    }

    /// Returns aggregate candidate outcomes for operator diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> &DiscoveryDiagnostics {
        &self.diagnostics
    }
}

/// Enumerates, validates, and atomically replaces one complete registry generation.
///
/// Individual transport/parse failures reject only that candidate. Duplicate
/// locators or validated identities reject the whole ambiguous replacement set.
///
/// # Errors
///
/// Returns a sanitized [`PlatformError`] for whole-pass enumeration, ambiguity,
/// or replacement failure while preserving the previous authoritative registry.
pub fn discover_validated_device_report<B: PlatformBackend>(
    backend: &mut B,
    registry: &mut DeviceRegistry,
) -> Result<ValidatedDiscoveryReport, PlatformError> {
    discover_with_protocol_refresh(backend, registry, None)
}

/// Reprobes the updated dock while preserving host-only refresh for other docks.
/// A stable USB/media identity cannot authorize reuse of pre-update INQUIRY or
/// configuration evidence. All normal same-handle readback checks still apply.
///
/// # Errors
/// Returns the same sanitized whole-pass errors as ordinary discovery.
pub fn discover_firmware_device_report<B: PlatformBackend>(
    backend: &mut B,
    registry: &mut DeviceRegistry,
    device_id: &DeviceId,
) -> Result<ValidatedDiscoveryReport, PlatformError> {
    discover_with_protocol_refresh(backend, registry, Some(device_id))
}

/// Private fresh inventory plus the still-open exact target probe lease.
pub(crate) struct FirmwareDiscoveryBinding {
    pub(crate) report: ValidatedDiscoveryReport,
    pub(crate) lease: Option<CandidateLease>,
}

/// Retains the target USB capture through subsequent firmware verification.
/// Releasing a successful probe can reset/rematch macOS storage and invalidate
/// the just-enumerated reopen recipe. No locator or handle crosses the service.
pub(crate) fn discover_firmware_device_binding<B: PlatformBackend>(
    backend: &mut B,
    registry: &mut DeviceRegistry,
    device_id: &DeviceId,
) -> Result<FirmwareDiscoveryBinding, PlatformError> {
    let mut lease = None;
    let result = validate_backend_candidates(backend, registry, Some(device_id), Some(&mut lease))
        .and_then(|(validated, diagnostics)| {
            registry
                .replace_validated(validated)
                .map(|snapshots| ValidatedDiscoveryReport::new(snapshots, diagnostics))
        });
    match result {
        Ok(report) => {
            backend.commit_candidate_refresh();
            Ok(FirmwareDiscoveryBinding { report, lease })
        }
        Err(error) => {
            backend.abort_candidate_refresh();
            Err(error)
        }
    }
}

/// Commits a complete discovery generation with optional target protocol refresh.
fn discover_with_protocol_refresh<B: PlatformBackend>(
    backend: &mut B,
    registry: &mut DeviceRegistry,
    fresh_device: Option<&DeviceId>,
) -> Result<ValidatedDiscoveryReport, PlatformError> {
    let result = validate_backend_candidates(backend, registry, fresh_device, None).and_then(
        |(validated, diagnostics)| {
            registry
                .replace_validated(validated)
                .map(|snapshots| ValidatedDiscoveryReport::new(snapshots, diagnostics))
        },
    );
    match result {
        Ok(report) => {
            backend.commit_candidate_refresh();
            Ok(report)
        }
        Err(error) => {
            backend.abort_candidate_refresh();
            Err(error)
        }
    }
}

/// Stages one complete discovery pass and commits it only when the selected
/// dock remains present with authoritative no-media evidence.
///
/// An empty, media-present, or otherwise inconclusive successful pass is
/// aborted before either the public registry or backend-private reopen recipes
/// change. This keeps post-eject UI suppression and operation authorization on
/// the same generation.
///
/// # Errors
///
/// Returns a sanitized whole-pass validation or replacement failure. `Ok(None)`
/// means the pass was valid but did not prove the required same-dock no-media
/// postcondition, so the previous generation remains authoritative.
pub fn discover_post_eject_report<B: PlatformBackend>(
    backend: &mut B,
    registry: &mut DeviceRegistry,
    device_id: &DeviceId,
) -> Result<Option<ValidatedDiscoveryReport>, PlatformError> {
    let result = validate_backend_candidates(backend, registry, None, None).and_then(
        |(validated, diagnostics)| {
            if !registry.staged_set_retains_device_without_media(&validated, device_id)? {
                return Ok(None);
            }
            registry
                .replace_validated(validated)
                .map(|snapshots| Some(ValidatedDiscoveryReport::new(snapshots, diagnostics)))
        },
    );
    match result {
        Ok(Some(report)) => {
            backend.commit_candidate_refresh();
            Ok(Some(report))
        }
        Ok(None) => {
            backend.abort_candidate_refresh();
            Ok(None)
        }
        Err(error) => {
            backend.abort_candidate_refresh();
            Err(error)
        }
    }
}

/// Returns only the authoritative snapshots for legacy internal callers.
///
/// # Errors
///
/// Returns the same sanitized whole-pass failures as
/// [`discover_validated_device_report`].
pub fn discover_validated_devices<B: PlatformBackend>(
    backend: &mut B,
    registry: &mut DeviceRegistry,
) -> Result<Vec<DeviceSnapshot>, PlatformError> {
    discover_validated_device_report(backend, registry)
        .map(ValidatedDiscoveryReport::into_snapshots)
}

/// Collects proven candidates and stable candidate-local rejection counts.
fn validate_backend_candidates<B: PlatformBackend>(
    backend: &mut B,
    registry: &DeviceRegistry,
    fresh_device: Option<&DeviceId>,
    mut retained_lease: Option<&mut Option<CandidateLease>>,
) -> Result<(Vec<ValidatedCandidate>, DiscoveryDiagnostics), PlatformError> {
    let platform = backend.capabilities();
    let candidates = backend.enumerate_candidates()?;
    if candidates.len() > super::MAX_CANDIDATE_DEVICES {
        return Err(PlatformError::TooManyCandidates);
    }
    reject_duplicate_candidates(&candidates)?;

    let candidate_count = candidates.len();
    let mut validated = Vec::with_capacity(candidate_count);
    let mut rejections = BTreeMap::new();
    /** Records one stable path-free candidate rejection. */
    fn reject(rejections: &mut BTreeMap<&'static str, usize>, reason: &'static str) {
        *rejections.entry(reason).or_default() += 1;
    }
    for candidate in candidates {
        if !metadata_is_sane(&candidate.metadata) {
            reject(&mut rejections, "candidate-validation-failed");
            continue;
        }
        if let Some(evidence) =
            registry.refresh_candidate_evidence(backend, &candidate, platform, fresh_device)?
        {
            validated.push(ValidatedCandidate {
                candidate,
                evidence,
                binding_continuity: true,
            });
            continue;
        }
        let mut lease = match backend.open_candidate(&candidate) {
            Ok(lease) => lease,
            Err(PlatformError::DeviceBusy) => {
                reject(&mut rejections, "media-mounted");
                continue;
            }
            Err(_) => {
                reject(&mut rejections, "candidate-validation-failed");
                continue;
            }
        };
        let Some(evidence) = revalidate_candidate_lease(&mut lease, &candidate, platform) else {
            reject(&mut rejections, "candidate-validation-failed");
            continue;
        };
        if let Some(retained) = retained_lease.as_deref_mut()
            && let Some(device_id) = fresh_device
            && registry.evidence_identifies_device(&evidence, device_id)?
        {
            *retained = Some(lease);
        }
        validated.push(ValidatedCandidate {
            candidate,
            evidence,
            binding_continuity: false,
        });
    }
    let rejections = rejections.into_iter().collect();
    let diagnostics = DiscoveryDiagnostics::new(candidate_count, validated.len(), rejections);
    Ok((validated, diagnostics))
}
