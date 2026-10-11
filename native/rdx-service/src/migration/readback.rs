// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed OpenRDX SPI readback; vendor READ BUFFER is unavailable on this receiver.

use super::{MigrationError, MigrationUsbIdentity, PreparedMigration};
use crate::protocol::{
    Command, InquiryPage, inquiry, openrdx_manufacturing_record_first,
    openrdx_manufacturing_record_second, openrdx_operational_state_record,
};
use crate::transport::CommandDispatch;

/// Private record observations from one retained OpenRDX BOT lease.
///
/// Deliberately lacks serialization and Debug: manufacturing includes opaque unit data.
pub struct MigrationReadback {
    usb: MigrationUsbIdentity,
    inquiry: Vec<u8>,
    manufacturing: Vec<u8>,
    state: Vec<u8>,
}

/// Reads only three fixed SPI ranges, bracketed by identical standard INQUIRY.
///
/// The native adapter must require BOT/LUN0 for the E7 commands. Neither source
/// firmware nor arbitrary addresses/opcodes can reach these reads through this API.
pub(crate) fn collect(
    usb: MigrationUsbIdentity,
    dispatch: &mut impl FnMut(&Command) -> CommandDispatch,
) -> Result<MigrationReadback, MigrationError> {
    let inquiry_command = inquiry(InquiryPage::Standard);
    let first = read(&inquiry_command, 64, dispatch)?;
    if !valid_receiver(&usb, &first) {
        return Err(MigrationError::ReadbackMismatch);
    }
    let mut manufacturing = read(&openrdx_manufacturing_record_first(), 128, dispatch)?;
    manufacturing.extend(read(&openrdx_manufacturing_record_second(), 128, dispatch)?);
    let state = read(&openrdx_operational_state_record(), 64, dispatch)?;
    if read(&inquiry_command, 64, dispatch)? != first {
        return Err(MigrationError::ReadbackMismatch);
    }
    Ok(MigrationReadback {
        usb,
        inquiry: first,
        manufacturing,
        state,
    })
}

/// Accepts only exact completed lengths; GOOD with partial/failed SPI data is insufficient.
fn read(
    command: &Command,
    length: usize,
    dispatch: &mut impl FnMut(&Command) -> CommandDispatch,
) -> Result<Vec<u8>, MigrationError> {
    let outcome = dispatch(command);
    let response = outcome.response().ok_or(MigrationError::ReadbackMismatch)?;
    if response.data().len() != length {
        return Err(MigrationError::ReadbackMismatch);
    }
    Ok(response.data().to_vec())
}

/// Requires the pinned receiver identity before any fixed private record request.
fn valid_receiver(usb: &MigrationUsbIdentity, inquiry: &[u8]) -> bool {
    usb.vendor_id == 0x1a5a
        && usb.product_id == 5
        && usb.location_id != 0
        && usb.serial.len() == 12
        && usb.serial.starts_with("00")
        && usb.serial.bytes().all(|byte| byte.is_ascii_digit())
        && inquiry.len() == 64
        && inquiry[0] & 31 == 0
        && inquiry[4] >= 31
        && usize::from(inquiry[4]) + 5 <= inquiry.len()
        && &inquiry[8..16] == b"TANDBERG"
        && &inquiry[16..32] == b"RDX             "
        && &inquiry[32..36] == b"0107"
}

impl PreparedMigration {
    /// Compares the complete preserved raw records, including their checksums.
    ///
    /// A fresh caller-owned lease supplies physical identity; the saved receipt
    /// remains independently checked. This proves the saved semantic reconstruction
    /// is present, not that unexposed vendor bytes were captured originally.
    pub fn verify_records(&self, readback: &MigrationReadback) -> Result<(), MigrationError> {
        self.verify_records_at_location(readback, self.capture.usb.location_id)
    }

    /// Checks the immutable unit records at one explicitly selected attempt location.
    ///
    /// Only this comparison uses the new nonzero location. The original capture,
    /// receipt and package remain unchanged; serial, vendor, receiver revision,
    /// product and every manufacturing/state byte retain their strict checks.
    /// The caller must independently authorize and observe the selected port.
    pub fn verify_records_at_location(
        &self,
        readback: &MigrationReadback,
        selected_location: u32,
    ) -> Result<(), MigrationError> {
        #[cfg(unix)]
        self.store.reopen()?;
        if selected_location == 0
            || !valid_receiver(&readback.usb, &readback.inquiry)
            || readback.usb.serial != self.capture.usb.serial
            || readback.usb.location_id != selected_location
            || readback.usb.vendor_id != self.capture.usb.vendor_id
            || readback.manufacturing != self.package[64..320]
            || readback.state != self.package[320..384]
        {
            return Err(MigrationError::ReadbackMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "readback_tests.rs"]
mod tests;
