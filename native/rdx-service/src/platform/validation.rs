// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Existing discovery command dispatch and exact identity/host validation.

use super::capability_projection::device_capabilities;
use super::media_status::media_status_evidence;
use super::status::{
    DriveLogProjection, ModeStatusProjection, cam_state_label, drive_error_label,
    drive_status_label, drive_status_projection, power_source_label,
};
use super::*;
use crate::protocol::{
    InquiryPage, RdxFeaturePage, inquiry, log_sense, mode_sense, parse_log_page,
    parse_rdx_inquiry_identity,
};

/// Revalidates a candidate lease without reopening or changing its exact handle.
pub(super) fn revalidate_candidate_lease(
    lease: &mut CandidateLease,
    candidate: &CandidateDevice,
    platform: PlatformCapabilities,
) -> Option<ValidatedEvidence> {
    diagnose_candidate_lease(lease, candidate, platform).ok()
}

/// Reports the fixed failing stage while retaining the exact existing dispatch/check order.
pub(super) fn diagnose_candidate_lease(
    lease: &mut CandidateLease,
    candidate: &CandidateDevice,
    platform: PlatformCapabilities,
) -> Result<ValidatedEvidence, DiscoveryFailure> {
    validate_open_handle(lease.handle.as_mut(), candidate, platform, true)
}

/// Revalidates a promoted lease without reopening or changing its exact handle.
pub(super) fn revalidate_device_lease(
    lease: &mut DeviceLease,
    candidate: &CandidateDevice,
    platform: PlatformCapabilities,
) -> Option<ValidatedEvidence> {
    validate_open_handle(lease.handle.as_mut(), candidate, platform, false).ok()
}

/// Executes the complete exact proof set through one already-open handle.
fn validate_open_handle(
    handle: &mut dyn PlatformDeviceHandle,
    candidate: &CandidateDevice,
    platform: PlatformCapabilities,
    apply_arrival_preference: bool,
) -> Result<ValidatedEvidence, DiscoveryFailure> {
    let standard = execute_probe(
        handle,
        DiscoveryProbe::StandardInquiry,
        inquiry(InquiryPage::Standard),
    )
    .ok_or(DiscoveryFailure::StandardInquiry)?;
    let identification = execute_probe(
        handle,
        DiscoveryProbe::DeviceIdentification,
        inquiry(InquiryPage::DeviceIdentification),
    )
    .ok_or(DiscoveryFailure::Vpd83Inquiry)?;
    let capability_bytes = execute_probe(
        handle,
        DiscoveryProbe::CapabilityPage,
        mode_sense(0x31).map_err(|_| DiscoveryFailure::CommandConfiguration)?,
    )
    .ok_or(DiscoveryFailure::Mode31Probe)?;
    let identity = parse_rdx_inquiry_identity(&standard, &identification)
        .map_err(|_| DiscoveryFailure::InquiryIdentity)?;
    let capability_page =
        RdxFeaturePage::parse(&capability_bytes).map_err(|_| DiscoveryFailure::Mode31Page)?;
    if capability_page.page_code() != 0x31 {
        return Err(DiscoveryFailure::Mode31Page);
    }
    if !metadata_matches(&candidate.metadata, &identity) {
        return Err(DiscoveryFailure::MetadataMismatch);
    }
    let (interface, product_family) =
        product_mapping(identity.product_type()).ok_or(DiscoveryFailure::Product)?;
    if candidate
        .metadata
        .interface
        .is_some_and(|hint| hint != interface)
    {
        return Err(DiscoveryFailure::Interface);
    }
    if apply_arrival_preference
        && platform.drive_letter_available()
        && interface == DeviceInterface::Usb3
    {
        let serial_key = serial_mapping_key(identity.serial());
        handle
            .apply_drive_letter_preference_on_arrival(&serial_key)
            .map_err(|_| DiscoveryFailure::ArrivalPreference)?;
    }
    let host_mutations_available = platform.safe_eject_available()
        || platform.force_eject_available()
        || platform.format_available()
        || platform.drive_letter_available();
    let host_facts = if host_mutations_available {
        let facts = handle
            .host_volume_facts()
            .map_err(|_| DiscoveryFailure::HostFacts)?;
        if facts.media_present != facts.media_fingerprint.is_some() {
            return Err(DiscoveryFailure::HostMediaEvidence);
        }
        Some(facts)
    } else {
        None
    };
    let available_drive_letters = if platform.drive_letter_available()
        && interface == DeviceInterface::Usb3
        && host_facts.is_some_and(|facts| !facts.media_present)
    {
        handle
            .available_drive_letters()
            .ok()
            .and_then(validate_available_drive_letters)
    } else {
        None
    };
    let capability_fingerprint = capability_fingerprint(
        identity.feature_mask_0(),
        identity.feature_mask_1(),
        capability_page.as_bytes(),
        platform,
    );
    let operation_mode_bytes = execute_probe(
        handle,
        DiscoveryProbe::OperationMode,
        mode_sense(0x34).map_err(|_| DiscoveryFailure::CommandConfiguration)?,
    );
    let operation_page = operation_mode_bytes
        .as_deref()
        .and_then(|bytes| RdxFeaturePage::parse(bytes).ok());
    let operation_mode = operation_page
        .as_ref()
        .and_then(|page| operation_mode_label(page.operation_mode()?));
    let sata_mode = operation_page
        .as_ref()
        .and_then(|page| sata_mode_label(page.max_host_sata_speed()?));
    let drive_status_bytes = execute_probe(
        handle,
        DiscoveryProbe::DriveStatus,
        log_sense(0x20).map_err(|_| DiscoveryFailure::CommandConfiguration)?,
    );
    let drive_status_page = drive_status_bytes
        .as_deref()
        .and_then(|bytes| parse_log_page(bytes).ok());
    let power_source = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0005)?.uint32())
        .and_then(power_source_label);
    let drive_status = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0000)?.uint32())
        .and_then(drive_status_label);
    let drive_load_count = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0001)?.uint32());
    let drive_errors = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0002)?.uint32())
        .map(drive_error_label);
    let cam_state = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0003)?.uint32())
        .and_then(cam_state_label);
    let mut drive = drive_status_projection(
        &identity,
        interface,
        product_family,
        ModeStatusProjection {
            operation_mode,
            sata_mode,
            response_available: operation_mode_bytes.is_some(),
        },
        DriveLogProjection {
            status: drive_status,
            load_count: drive_load_count,
            errors: drive_errors,
            cam_state,
            power_source,
            response_available: drive_status_bytes.is_some(),
        },
    );
    let mut media_status = if host_facts.is_some_and(|facts| facts.media_present) {
        let media_identification = execute_probe(
            handle,
            DiscoveryProbe::MediaIdentification,
            inquiry(InquiryPage::MediaIdentification),
        );
        let media_device = execute_probe(
            handle,
            DiscoveryProbe::MediaDevice,
            inquiry(InquiryPage::MediaDevice),
        );
        let cartridge_status = execute_probe(
            handle,
            DiscoveryProbe::CartridgeStatus,
            log_sense(0x21).map_err(|_| DiscoveryFailure::CommandConfiguration)?,
        );
        let temperature = execute_probe(
            handle,
            DiscoveryProbe::Temperature,
            log_sense(0x0D).map_err(|_| DiscoveryFailure::CommandConfiguration)?,
        );
        media_status_evidence(
            media_identification,
            media_device,
            cartridge_status,
            temperature,
        )
    } else {
        MediaStatusEvidence::default()
    };
    drive.available_drive_letters = available_drive_letters;
    let volume_label = if host_facts.is_some_and(|facts| facts.mounted) {
        handle.host_volume_label().ok().flatten()
    } else {
        None
    };
    let capabilities = device_capabilities(
        identity.feature_mask_1() & 0x10 != 0,
        interface,
        platform,
        host_facts,
        sata_mode.is_some(),
        volume_label.is_some(),
    );
    media_status.volume_label = volume_label;
    Ok(ValidatedEvidence {
        vendor: identity.vendor().to_owned(),
        product: identity.product().to_owned(),
        serial: identity.serial().to_owned(),
        revision: identity.revision().to_owned(),
        interface,
        product_family,
        capabilities,
        capability_fingerprint,
        host_facts,
        drive,
        media_status,
        drive_mode_supported: identity.feature_mask_1() & 0x10 != 0,
        sata_mode_reported: sata_mode.is_some(),
    })
}

/// Accepts only the bounded sorted unique D-Z projection promised to the renderer.
pub(super) fn validate_available_drive_letters(
    letters: Vec<DriveLetter>,
) -> Option<Vec<DriveLetter>> {
    if letters.len() > 23
        || letters.iter().any(|letter| letter.get() < 'D')
        || letters
            .windows(2)
            .any(|pair| pair[0].get() >= pair[1].get())
    {
        return None;
    }
    Some(letters)
}

/// Maps only the supported operation-mode values from MODE page `0x34`.
const fn operation_mode_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("Not configured"),
        1 => Some("Removable"),
        2 => Some("Fixed disk"),
        3 => Some("Remove device with cartridge"),
        _ => None,
    }
}

/// Maps only the two supported Manager SATA III link-mode values.
const fn sata_mode_label(value: u8) -> Option<&'static str> {
    match value {
        2 => Some("1.5g-3g"),
        3 => Some("3g-6g"),
        _ => None,
    }
}

/// Dispatches one immutable discovery command and retains only proven response bytes.
pub(super) fn execute_probe(
    handle: &mut dyn PlatformDeviceHandle,
    probe: DiscoveryProbe,
    command: Command,
) -> Option<Vec<u8>> {
    let command = command.with_timeout_ms(DISCOVERY_PROBE_TIMEOUT_MS).ok()?;
    let command = DiscoveryCommand { probe, command };
    handle
        .execute(command.command())
        .response()
        .map(|response| response.data().to_vec())
}

/// Rejects duplicate safe tokens or exact private locators before any probe runs.
pub(super) fn reject_duplicate_candidates(
    candidates: &[CandidateDevice],
) -> Result<(), PlatformError> {
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[..index]
            .iter()
            .any(|earlier| earlier.token == candidate.token || earlier.locator == candidate.locator)
        {
            return Err(PlatformError::DuplicateCandidate);
        }
    }
    Ok(())
}

/// Requires every present OS hint to be printable, bounded, and exactly corroborated.
fn metadata_matches(
    metadata: &CandidateMetadata,
    identity: &crate::protocol::RdxInquiryIdentity,
) -> bool {
    hint_matches(metadata.vendor.as_deref(), identity.vendor())
        && hint_matches(metadata.product.as_deref(), identity.product())
        && hint_matches(metadata.serial.as_deref(), identity.serial())
}

/// Rejects hostile text shapes before spending any transport work on a candidate.
pub(super) fn metadata_is_sane(metadata: &CandidateMetadata) -> bool {
    [
        metadata.vendor.as_deref(),
        metadata.product.as_deref(),
        metadata.serial.as_deref(),
    ]
    .into_iter()
    .all(|hint| hint.is_none_or(hint_is_sane))
}

/// Checks one optional untrusted text hint without normalizing hostile content.
fn hint_matches(hint: Option<&str>, exact: &str) -> bool {
    hint.is_none_or(|hint| hint_is_sane(hint) && hint == exact)
}

/// Accepts only bounded, trimmed, printable ASCII enumeration text.
fn hint_is_sane(hint: &str) -> bool {
    !hint.is_empty()
        && hint.len() <= MAX_METADATA_LENGTH
        && hint.trim() == hint
        && hint.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
}

/// Maps only supported Manager product enumerations to Phase 2 session families.
fn product_mapping(product_type: u8) -> Option<(DeviceInterface, ProductFamily)> {
    match product_type {
        0..=6 => Some((DeviceInterface::Legacy, ProductFamily::Usb2Sata1)),
        0x35..=0x38 => Some((DeviceInterface::Usb3, ProductFamily::Usb3Sata3)),
        0x39 => Some((DeviceInterface::Sata3, ProductFamily::Usb3Sata3)),
        _ => None,
    }
}
