// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable plans bind one original sector and replacement to one exact USB location.

use super::{
    Result,
    record::{self, RecordState, Sector},
};
use serde::{Deserialize, Serialize};

/// Plan fields are verified against the private sector before every hardware attempt.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Plan {
    pub schema_version: u8,
    pub kind: String,
    pub usb_vendor_id: u16,
    pub usb_product_id: u16,
    pub usb_location_id: u32,
    pub expected_usb_serial: String,
    pub new_usb_serial: String,
    pub reconstruct_erased: bool,
    pub original_factory_data_lost: bool,
    pub original_record_state: RecordState,
    pub sector_sha256: String,
    pub sector_crc32: u32,
    pub expected_sector_sha256: String,
}

impl Plan {
    /// Creates a closed immutable plan after validating the expected record transition.
    pub fn new(
        sector: &Sector,
        serial: String,
        location: u32,
        new_serial: String,
        reconstruct: bool,
    ) -> Result<Self> {
        record::validate_usb_serial(&serial)?;
        if location == 0 {
            return Err("serial-location-required");
        }
        let expected = record::expected_sector(sector, &new_serial, reconstruct)?;
        if expected == *sector {
            return Err("serial-already-set");
        }
        Ok(Self {
            schema_version: 1,
            kind: "openrdx-serial-plan".into(),
            usb_vendor_id: 0x1a5a,
            usb_product_id: 5,
            usb_location_id: location,
            expected_usb_serial: serial,
            new_usb_serial: new_serial,
            reconstruct_erased: reconstruct,
            original_factory_data_lost: reconstruct,
            original_record_state: record::state(sector),
            sector_sha256: record::sha256(sector),
            sector_crc32: record::crc32(sector),
            expected_sector_sha256: record::sha256(&expected),
        })
    }

    /// Recomputes every derived field so edited, stale, or inconsistent plans fail closed.
    pub fn validate(&self, sector: &Sector) -> Result<()> {
        let canonical = Self::new(
            sector,
            self.expected_usb_serial.clone(),
            self.usb_location_id,
            self.new_usb_serial.clone(),
            self.reconstruct_erased,
        )?;
        if serde_json::to_value(self).ok() != serde_json::to_value(canonical).ok() {
            return Err("serial-plan-evidence-mismatch");
        }
        Ok(())
    }

    /// Requires exact selected USB identity and complete fresh sector equality before mutation.
    pub fn validate_live(
        &self,
        backup: &Sector,
        fresh: &Sector,
        serial: &str,
        location: u32,
    ) -> Result<()> {
        self.validate(backup)?;
        if serial != self.expected_usb_serial || location != self.usb_location_id {
            return Err("serial-target-identity-changed");
        }
        if backup != fresh {
            return Err("serial-plan-stale");
        }
        Ok(())
    }
}
