// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded cartridge evidence decoded from optional read-only status probes.

use crate::protocol::{
    CartridgeIdentity, parse_cartridge_identity, parse_log_page, parse_temperature_celsius,
};

/// Parsed, renderer-independent cartridge evidence from optional read-only probes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct MediaStatusEvidence {
    pub(super) identity: Option<CartridgeIdentity>,
    pub(super) volume_label: Option<crate::model::VolumeLabel>,
    pub(super) status: Option<String>,
    pub(super) load_count: Option<u32>,
    pub(super) bytes_written: Option<u64>,
    pub(super) bytes_read: Option<u64>,
    pub(super) write_protected: Option<bool>,
    pub(super) temperature_celsius: Option<u8>,
    pub(super) identity_response_available: bool,
    pub(super) status_response_available: bool,
    pub(super) temperature_response_available: bool,
}

/// Decodes successful optional cartridge responses without rejecting the drive.
pub(super) fn media_status_evidence(
    media_identification: Option<Vec<u8>>,
    media_device: Option<Vec<u8>>,
    cartridge_status: Option<Vec<u8>>,
    temperature: Option<Vec<u8>>,
) -> MediaStatusEvidence {
    let identity = media_identification
        .as_deref()
        .zip(media_device.as_deref())
        .and_then(|(identification, device)| parse_cartridge_identity(identification, device).ok());
    let cartridge_page = cartridge_status
        .as_deref()
        .and_then(|bytes| parse_log_page(bytes).ok());
    MediaStatusEvidence {
        identity,
        volume_label: None,
        status: cartridge_page
            .as_ref()
            .and_then(|page| page.find(0x0000)?.uint32())
            .map(cartridge_status_label),
        load_count: cartridge_page
            .as_ref()
            .and_then(|page| page.find(0x0001)?.uint32()),
        bytes_written: cartridge_page
            .as_ref()
            .and_then(|page| page.find(0x0005)?.uint32())
            .map(megabytes_to_bytes),
        bytes_read: cartridge_page
            .as_ref()
            .and_then(|page| page.find(0x0006)?.uint32())
            .map(megabytes_to_bytes),
        write_protected: cartridge_page
            .as_ref()
            .and_then(|page| page.find(0x0008)?.uint32())
            .map(|flags| flags != 0),
        temperature_celsius: temperature
            .as_deref()
            .and_then(|bytes| parse_temperature_celsius(bytes).ok().flatten()),
        identity_response_available: media_identification.is_some() && media_device.is_some(),
        status_response_available: cartridge_status.is_some(),
        temperature_response_available: temperature.is_some(),
    }
}

/// Maps the specified zero/nonzero cartridge-health contract.
fn cartridge_status_label(value: u32) -> String {
    if value == 0 {
        "Good".to_owned()
    } else {
        "Cartridge error".to_owned()
    }
}

/// Converts the original Manager's decimal-megabyte counters to bytes.
fn megabytes_to_bytes(value: u32) -> u64 {
    u64::from(value) * 1_000_000
}
