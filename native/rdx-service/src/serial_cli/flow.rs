// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Testable serial transaction ordering, physical-bay checks, and full-sector verification.

use super::{
    Result, Target,
    plan::Plan,
    record::{self, Sector},
};

/// This flow cannot request arbitrary addresses, commands, modes, or firmware operations.
pub(super) trait SerialTransport {
    /// Reads fresh fixed standard INQUIRY data.
    fn inquiry(&mut self) -> Result<Vec<u8>>;
    /// Reads fresh fixed drive LOG SENSE framing.
    fn drive_log(&mut self) -> Result<Vec<u8>>;
    /// Reads fixed mechanism diagnostics including raw physical cartridge sensor input.
    fn mechanism_diagnostics(&mut self) -> Result<Vec<u8>>;
    /// Reads one semantic fixed 128-byte sector chunk.
    fn sector_chunk(&mut self, index: u8) -> Result<Vec<u8>>;
    /// Requires GOOD for the no-payload and non-mutating serial capability command.
    fn capability(&mut self) -> Result<()>;
    /// Sends only the closed, prevalidated serial compare-and-set request.
    fn set_serial(&mut self, payload: Vec<u8>) -> Result<()>;
}

/// Requires fresh RDX identity and the full standard reply's declared byte range.
fn inquiry_revision(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 43
        || bytes.len() > 254
        || usize::from(bytes[4]) + 5 != bytes.len()
        || bytes[0] & 0x1f != 0
        || &bytes[8..16] != b"TANDBERG"
        || &bytes[16..32] != b"RDX             "
        || &bytes[37..40] != b"RDX"
        || !bytes[32..36].iter().all(u8::is_ascii_digit)
    {
        return Err("serial-inquiry-identity-invalid");
    }
    // This protocol belongs to OpenRDX 1.xx, not a vendor revision accepting unrelated buffer IDs.
    if &bytes[32..34] != b"01" {
        return Err("serial-requires-openrdx-firmware");
    }
    Ok(std::str::from_utf8(&bytes[32..36])
        .map_err(|_| "serial-inquiry-identity-invalid")?
        .into())
}

/// Requires complete fresh drive status, then the independent active-low GPIO5 cartridge sensor.
fn require_empty_bay(transport: &mut impl SerialTransport) -> Result<()> {
    let bytes = transport.drive_log()?;
    let page = rdx_service::protocol::parse_log_page(&bytes)
        .map_err(|_| "serial-drive-log-evidence-incomplete")?;
    if page.page_code() != 0x20 {
        return Err("serial-drive-log-evidence-incomplete");
    }
    let diagnostics = transport.mechanism_diagnostics()?;
    if diagnostics.len() != 128 || &diagnostics[..4] != b"RDXM" || diagnostics[4] != 1 {
        return Err("serial-physical-bay-evidence-incomplete");
    }
    // GPIO2 is the mechanism CAM input and cannot prove cartridge absence.
    // GPIO5 is active low: a high bit proves the bay sensor reports absent.
    if diagnostics[10] & 0x20 == 0 {
        return Err("serial-physical-bay-not-empty");
    }
    if diagnostics[5] != 0 {
        return Err("serial-mechanism-not-idle");
    }
    Ok(())
}

/// Reads all chunks in order, rejecting short or oversized replies without partial evidence.
fn whole_sector(transport: &mut impl SerialTransport) -> Result<Sector> {
    let mut sector = [0; 4096];
    for index in 0..32 {
        let bytes = transport.sector_chunk(index)?;
        if bytes.len() != 128 {
            return Err("serial-sector-read-incomplete");
        }
        sector[usize::from(index) * 128..(usize::from(index) + 1) * 128].copy_from_slice(&bytes);
    }
    Ok(sector)
}

/// Brackets a full-sector read with fresh identity and physical-bay evidence.
pub(super) fn snapshot(transport: &mut impl SerialTransport) -> Result<(Sector, String)> {
    let inquiry = transport.inquiry()?;
    let revision = inquiry_revision(&inquiry)?;
    require_empty_bay(transport)?;
    let sector = whole_sector(transport)?;
    if transport.inquiry()? != inquiry {
        return Err("serial-inquiry-identity-changed");
    }
    require_empty_bay(transport)?;
    Ok((sector, revision))
}

/// Verifies every byte before and after the single write; capability failure never mutates.
pub(super) fn apply_record(
    transport: &mut impl SerialTransport,
    plan: &Plan,
    backup: &Sector,
    target: &Target,
    mut before_write: impl FnMut() -> Result<()>,
) -> Result<Sector> {
    plan.validate(backup)?;
    let (fresh, _) = snapshot(transport)?;
    plan.validate_live(backup, &fresh, &target.serial, target.location)?;
    transport
        .capability()
        .map_err(|_| "serial-capability-unavailable-no-write")?;
    // Refresh physical evidence immediately before committing durable attempt intent.
    inquiry_revision(&transport.inquiry()?)?;
    require_empty_bay(transport)?;
    before_write()?;
    transport
        .set_serial(record::payload(
            backup,
            &plan.new_usb_serial,
            plan.reconstruct_erased,
        )?)
        .map_err(|_| "serial-write-failed-or-uncertain-retain-plan-and-backup")?;
    let readback =
        whole_sector(transport).map_err(|_| "serial-write-readback-incomplete-no-reset")?;
    let expected = record::expected_sector(backup, &plan.new_usb_serial, plan.reconstruct_erased)?;
    if readback != expected {
        return Err("serial-write-readback-mismatch-no-reset");
    }
    Ok(readback)
}
