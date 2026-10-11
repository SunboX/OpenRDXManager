// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Renderer-safe projection of private authoritative cartridge facts.

use crate::model::{
    DisplayText, Media, MediaStatusDetails, OpaqueId, ReasonCode, SafeJsonInteger, StatusField,
};
use crate::operations::{FileSystem, HostVolumeFacts};

use super::super::MediaStatusEvidence;

/// Derives renderer-safe current-media metadata from private authoritative facts.
pub(super) fn renderer_media(
    facts: HostVolumeFacts,
    evidence: &MediaStatusEvidence,
) -> Option<Media> {
    let fingerprint = facts.media_fingerprint?;
    if !facts.media_present {
        return None;
    }
    let mut id = String::from("media:");
    for byte in fingerprint {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").expect("writing a digest to String cannot fail");
    }
    let capacity_bytes = SafeJsonInteger::new(facts.capacity_bytes).ok();
    // An unmounted volume has no filesystem accounting sample. Native adapters
    // use zero in that state as an absence sentinel, never as "zero bytes free".
    let free_bytes = facts
        .mounted
        .then(|| SafeJsonInteger::new(facts.free_bytes).ok())
        .flatten();
    let used_bytes = facts
        .mounted
        .then(|| {
            facts
                .capacity_bytes
                .checked_sub(facts.free_bytes)
                .and_then(|used| SafeJsonInteger::new(used).ok())
        })
        .flatten();
    let identity_reason = probe_reason(evidence.identity_response_available);
    let status_reason = probe_reason(evidence.status_response_available);
    let temperature_reason = if evidence.temperature_response_available {
        "not-reported"
    } else {
        "status-probe-unavailable"
    };
    let serial = evidence
        .identity
        .as_ref()
        .and_then(|identity| DisplayText::new(identity.serial()).ok());
    let status = evidence
        .status
        .as_deref()
        .and_then(|value| DisplayText::new(value).ok());
    let write_protected = evidence.write_protected.unwrap_or(!facts.writable);
    let details = MediaStatusDetails {
        vendor: identity_text(evidence, identity_reason, |identity| identity.vendor()),
        model: identity_text(evidence, identity_reason, |identity| identity.model()),
        serial_number: serial.clone().map_or_else(
            || StatusField::unavailable(identity_reason),
            StatusField::reported,
        ),
        status: status.clone().map_or_else(
            || StatusField::unavailable(status_reason),
            StatusField::reported,
        ),
        load_count: status_u64(evidence.load_count.map(u64::from), status_reason),
        hdd_firmware: identity_text(evidence, identity_reason, |identity| {
            identity.hdd_firmware()
        }),
        cartridge_type: StatusField::reported(
            DisplayText::new("Disk").expect("static cartridge type is renderer-safe"),
        ),
        write_protected: StatusField::reported(write_protected),
        temperature_celsius: status_u64(
            evidence.temperature_celsius.map(u64::from),
            temperature_reason,
        ),
        capacity_bytes: status_number(capacity_bytes),
        used_bytes: if facts.mounted {
            status_number(used_bytes)
        } else {
            StatusField::unavailable("media-not-mounted")
        },
        free_bytes: if facts.mounted {
            status_number(free_bytes)
        } else {
            StatusField::unavailable("media-not-mounted")
        },
        mounted: StatusField::reported(facts.mounted),
        bytes_read: status_u64(evidence.bytes_read, status_reason),
        bytes_written: status_u64(evidence.bytes_written, status_reason),
        encrypted: StatusField::unavailable("not-reported"),
        support_status: if evidence.status_response_available {
            StatusField::reported(
                ReasonCode::new("cartridge-status-page-available")
                    .expect("static support status is valid"),
            )
        } else {
            StatusField::unavailable("status-probe-unavailable")
        },
        sense_summary: StatusField::unavailable("no-safe-sense-available"),
    };
    Some(Media {
        id: OpaqueId::new(id).expect("fixed media digest is a bounded opaque ID"),
        serial,
        label: evidence.volume_label.clone(),
        capacity_bytes,
        used_bytes,
        writable: Some(!write_protected),
        encrypted: None,
        filesystem: facts.filesystem.map(|filesystem| {
            DisplayText::new(match filesystem {
                FileSystem::Ntfs => "ntfs",
                FileSystem::ExFat => "exfat",
                FileSystem::MacOs(filesystem) | FileSystem::Linux(filesystem) => {
                    filesystem.wire_name()
                }
            })
            .expect("static filesystem labels are renderer-safe")
        }),
        status: evidence.status.as_deref().and_then(status_reason_code),
        details,
    })
}

/// Selects a stable absence reason based on whether a response reached decoding.
const fn probe_reason(response_available: bool) -> &'static str {
    if response_available {
        "field-decoder-unavailable"
    } else {
        "status-probe-unavailable"
    }
}

/// Projects one bounded cartridge identity string.
fn identity_text(
    evidence: &MediaStatusEvidence,
    reason: &'static str,
    selector: fn(&crate::protocol::CartridgeIdentity) -> &str,
) -> StatusField<DisplayText> {
    evidence
        .identity
        .as_ref()
        .and_then(|identity| DisplayText::new(selector(identity)).ok())
        .map_or_else(|| StatusField::unavailable(reason), StatusField::reported)
}

/// Projects one optional counter through the JSON-safe integer bound.
fn status_u64(value: Option<u64>, reason: &'static str) -> StatusField<SafeJsonInteger> {
    value
        .and_then(|number| SafeJsonInteger::new(number).ok())
        .map_or_else(|| StatusField::unavailable(reason), StatusField::reported)
}

/// Converts the reported health label to the stable legacy status code.
fn status_reason_code(value: &str) -> Option<ReasonCode> {
    ReasonCode::new(match value {
        "Good" => "good",
        "Cartridge error" => "cartridge-error",
        _ => return None,
    })
    .ok()
}

/// Converts a bounded host byte count into an explicit status field.
fn status_number(value: Option<SafeJsonInteger>) -> StatusField<SafeJsonInteger> {
    value.map_or_else(
        || StatusField::unavailable("field-value-invalid"),
        StatusField::reported,
    )
}
