// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact CDB and transfer-buffer builders supported by the RDX Manager implementation reference.

use super::ProtocolBuildError;
use super::endian::{MAX_U24, u16_be, u24_be, u32_be};

#[path = "manufacturing.rs"]
mod manufacturing;
pub use manufacturing::{
    openrdx_manufacturing_restore_capability, openrdx_manufacturing_sector_chunk,
    openrdx_mechanism_diagnostics, openrdx_restore_manufacturing, openrdx_serial_capability,
};

const LOG_SENSE_ALLOCATION_LENGTH: usize = 0xFE;
const MODE_SENSE_ALLOCATION_LENGTH: usize = 0xFE;
const SECURITY_ALLOCATION_LENGTH: usize = 0x1000;
const MODE_PARAMETER_HEADER_LENGTH: usize = 8;
const MODE_PAGE_HEADER_LENGTH: usize = 2;

/// Default host-side command timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u32 = 30_000;
/// Largest host-side command timeout accepted by the platform-neutral layer.
pub const MAX_TIMEOUT_MS: u32 = 300_000;

/// Direction of a command transfer relative to the RDX device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataDirection {
    /// The command carries no data phase.
    None,
    /// The device returns data to the host.
    FromDevice,
    /// The host sends data to the device.
    ToDevice,
}

/// Exact INQUIRY variants used to establish one manageable RDX identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InquiryPage {
    /// Standard INQUIRY data, including the RDX capability extension.
    Standard,
    /// fixed-layout device-identification VPD page `0x83`.
    DeviceIdentification,
    /// variable-width cartridge-identification VPD page `0xC0`.
    MediaIdentification,
    /// ATA identify-device cartridge VPD page `0xC2`.
    MediaDevice,
}

/// Immutable SCSI command, transfer storage, direction, and host timeout.
///
/// Commands can only be created by the evidence-bounded builders in this
/// module. The native service accepts high-level operation requests and never
/// accepts a renderer- or client-supplied `Command` or raw CDB.
#[derive(Clone, Eq, PartialEq)]
pub struct Command {
    cdb: Box<[u8]>,
    direction: DataDirection,
    data: zeroize::Zeroizing<Vec<u8>>,
    timeout_ms: u32,
}

impl std::fmt::Debug for Command {
    /// Redacts authorization and complete manufacturing records from command diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.cdb() == [0x3b, 2, 0x80, 0, 0, 0, 0, 0, 10, 0]
            || self.cdb() == [0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0]
        {
            return formatter.write_str("Command(<private>)");
        }
        formatter
            .debug_struct("Command")
            .field("cdb", &self.cdb)
            .field("direction", &self.direction)
            .field("data", &self.data)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Command {
    /// Returns the exact immutable command descriptor block bytes.
    #[must_use]
    pub fn cdb(&self) -> &[u8] {
        &self.cdb
    }

    /// Returns the command's data direction.
    #[must_use]
    pub const fn direction(&self) -> DataDirection {
        self.direction
    }

    /// Returns the owned transfer buffer used by this command.
    ///
    /// For data-in commands this is zero-initialized receive storage. For
    /// data-out commands it is the exact outgoing payload. No-data commands
    /// return an empty slice.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the outgoing payload, or an empty slice for other directions.
    #[must_use]
    pub fn data_out(&self) -> &[u8] {
        if self.direction == DataDirection::ToDevice {
            &self.data
        } else {
            &[]
        }
    }

    /// Returns the allocated receive capacity, or zero for other directions.
    #[must_use]
    pub fn data_in_capacity(&self) -> usize {
        if self.direction == DataDirection::FromDevice {
            self.data.len()
        } else {
            0
        }
    }

    /// Returns the bounded host transport timeout in whole milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// Replaces the host timeout without changing CDB or payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolBuildError::TimeoutOutOfRange`] for zero or for a
    /// value above [`MAX_TIMEOUT_MS`].
    pub fn with_timeout_ms(mut self, milliseconds: u32) -> Result<Self, ProtocolBuildError> {
        if !(1..=MAX_TIMEOUT_MS).contains(&milliseconds) {
            return Err(ProtocolBuildError::TimeoutOutOfRange { milliseconds });
        }
        self.timeout_ms = milliseconds;
        Ok(self)
    }

    /// Creates an immutable command after its builder has validated every field.
    fn new(cdb: impl Into<Box<[u8]>>, direction: DataDirection, data: Vec<u8>) -> Self {
        Self {
            cdb: cdb.into(),
            direction,
            data: zeroize::Zeroizing::new(data),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// Builds the exact no-data RDX SEND DIAGNOSTIC self-test command.
#[must_use]
pub fn self_test() -> Command {
    Command::new(
        [0x1D, 0x04, 0x00, 0x00, 0x00, 0x00],
        DataDirection::None,
        Vec::new(),
    )
}

/// Builds the exact RDX LED diagnostic on or off/cleanup command.
///
/// `true` encodes test value `0`; `false` encodes cleanup value `1`.
#[must_use]
pub fn led_test(on: bool) -> Command {
    let value = u32::from(!on);
    let mut payload = vec![0x80, 0x00, 0x00, 0x04];
    payload.extend_from_slice(&u32_be(value));
    Command::new(
        [0x1D, 0x00, 0x00, 0x00, 0x08, 0x00],
        DataDirection::ToDevice,
        payload,
    )
}

/// Builds the exact no-data RDX unit-reset command used after SATA mode changes.
#[must_use]
pub fn unit_reset() -> Command {
    Command::new(
        [0x1D, 0x05, 0x00, 0x00, 0x00, 0x00],
        DataDirection::None,
        Vec::new(),
    )
}

/// Reads the complete researched version-6 factory response, without arbitrary addressing.
#[must_use]
pub fn vendor_0283_factory_info() -> Command {
    Command::new(
        [0x3C, 0x02, 0x02, 0, 0, 0, 0, 0, 0xAC, 0],
        DataDirection::FromDevice,
        vec![0; 172],
    )
}

/// Reads the complete researched USB identity response on the same selected dock.
#[must_use]
pub fn vendor_0283_usb_identity() -> Command {
    Command::new(
        [0x3C, 0x02, 0x0A, 0, 0, 0, 0, 0, 0x20, 0],
        DataDirection::FromDevice,
        vec![0; 32],
    )
}

/// Builds one exact bounded INQUIRY command used by trusted discovery.
#[must_use]
pub fn inquiry(page: InquiryPage) -> Command {
    let (enable_vpd, page_code, allocation_length) = match page {
        InquiryPage::Standard => (0, 0, 0x00FE_u16),
        InquiryPage::DeviceIdentification => (1, 0x83, 0x00FE),
        InquiryPage::MediaIdentification => (1, 0xC0, 0x00FE),
        InquiryPage::MediaDevice => (1, 0xC2, 0x0200),
    };
    let [allocation_high, allocation_low] = allocation_length.to_be_bytes();
    Command::new(
        [
            0x12,
            enable_vpd,
            page_code,
            allocation_high,
            allocation_low,
            0,
        ],
        DataDirection::FromDevice,
        vec![0; usize::from(allocation_length)],
    )
}

/// Builds an exact RDX LOG SENSE command for a proven page.
///
/// # Errors
///
/// Returns [`ProtocolBuildError::UnsupportedLogPage`] unless `page` is the
/// drive page `0x20` or cartridge page `0x21`.
pub fn log_sense(page: u8) -> Result<Command, ProtocolBuildError> {
    validate_log_page(page)?;
    Ok(Command::new(
        [0x4D, 0x00, page, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00],
        DataDirection::FromDevice,
        vec![0; LOG_SENSE_ALLOCATION_LENGTH],
    ))
}

/// Builds an exact MODE SENSE(10) command for a proven RDX page.
///
/// # Errors
///
/// Returns [`ProtocolBuildError::UnsupportedModePage`] unless `page` is one
/// of the RDX pages `0x31`, `0x33`, or `0x34`.
pub fn mode_sense(page: u8) -> Result<Command, ProtocolBuildError> {
    validate_mode_page(page)?;
    Ok(Command::new(
        [0x5A, 0x00, page, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00],
        DataDirection::FromDevice,
        vec![0; MODE_SENSE_ALLOCATION_LENGTH],
    ))
}

/// Converts one complete MODE SENSE(10) response into MODE SELECT(10).
///
/// The response's total length, block-descriptor length, page code, and page
/// length must agree with the supplied bytes. The conversion preserves all
/// unrelated bytes while clearing the three response-only header bytes.
///
/// # Errors
///
/// Returns a payload size or consistency error for truncated, oversized, or
/// internally inconsistent responses. Returns
/// [`ProtocolBuildError::UnsupportedModePage`] for a page outside the exact
/// RDX page allowlist.
pub fn mode_select(payload: &[u8], save_pages: bool) -> Result<Command, ProtocolBuildError> {
    if payload.len() > usize::from(u16::MAX) {
        return Err(ProtocolBuildError::PayloadTooLarge {
            context: "MODE SELECT payload",
            maximum: usize::from(u16::MAX),
            actual: payload.len(),
        });
    }
    let minimum = MODE_PARAMETER_HEADER_LENGTH + MODE_PAGE_HEADER_LENGTH;
    if payload.len() < minimum {
        return Err(ProtocolBuildError::PayloadTooShort {
            context: "MODE SENSE payload",
            minimum,
            actual: payload.len(),
        });
    }

    let declared_total = usize::from(u16::from_be_bytes([payload[0], payload[1]])) + 2;
    require_length("MODE SENSE total length", declared_total, payload.len())?;

    let block_descriptor_length = usize::from(u16::from_be_bytes([payload[6], payload[7]]));
    let page_offset = MODE_PARAMETER_HEADER_LENGTH
        .checked_add(block_descriptor_length)
        .ok_or(ProtocolBuildError::PayloadLengthMismatch {
            context: "MODE block descriptor length",
            declared: block_descriptor_length,
            actual: payload.len() - MODE_PARAMETER_HEADER_LENGTH,
        })?;
    if page_offset + MODE_PAGE_HEADER_LENGTH > payload.len() {
        return Err(ProtocolBuildError::PayloadLengthMismatch {
            context: "MODE block descriptor length",
            declared: block_descriptor_length,
            actual: payload.len() - MODE_PARAMETER_HEADER_LENGTH,
        });
    }

    let page_header = payload[page_offset];
    let page = page_header & 0x3F;
    if page_header & 0x40 != 0 {
        return Err(ProtocolBuildError::UnsupportedModeSubpage(page));
    }
    validate_mode_page(page)?;
    let declared_page_body_length = usize::from(payload[page_offset + 1]);
    let declared_page_length = declared_page_body_length + MODE_PAGE_HEADER_LENGTH;
    require_length(
        "MODE page length",
        declared_page_length,
        payload.len() - page_offset,
    )?;
    let minimum_page_body_length = minimum_mode_page_body_length(page);
    if declared_page_body_length < minimum_page_body_length {
        return Err(ProtocolBuildError::PayloadTooShort {
            context: mode_page_context(page),
            minimum: minimum_page_body_length,
            actual: declared_page_body_length,
        });
    }

    let parameter_length =
        u16::try_from(payload.len()).map_err(|_| ProtocolBuildError::PayloadTooLarge {
            context: "MODE SELECT payload",
            maximum: usize::from(u16::MAX),
            actual: payload.len(),
        })?;
    let length = u16_be(parameter_length);
    let mut output = payload.to_vec();
    // SetupModeSelect10 clears the two-byte MODE DATA LENGTH and
    // medium-type byte while preserving device-specific, descriptor, PS, and
    // page data bytes from the successful MODE SENSE response.
    output[0..3].fill(0);

    Ok(Command::new(
        [
            0x55,
            0x10 | u8::from(save_pages),
            0,
            0,
            0,
            0,
            0,
            length[0],
            length[1],
            0,
        ],
        DataDirection::ToDevice,
        output,
    ))
}

/// Builds the SECURITY PROTOCOL IN command for an observed selector.
///
/// Selector acceptance records only that `0x0010`, `0x0020`, and `0x0021`
/// occur in the query family; it assigns no unproven operation
/// meaning.
///
/// # Errors
///
/// Returns [`ProtocolBuildError::UnsupportedSecuritySelector`] for any
/// selector outside the allowlist.
pub fn security_in(selector: u16) -> Result<Command, ProtocolBuildError> {
    validate_security_in_selector(selector)?;
    let selector = u16_be(selector);
    Ok(Command::new(
        [
            0xA2,
            0x20,
            selector[0],
            selector[1],
            0,
            0,
            0,
            0,
            0x10,
            0,
            0,
            0,
        ],
        DataDirection::FromDevice,
        vec![0; SECURITY_ALLOCATION_LENGTH],
    ))
}

/// Applies the SECURITY PROTOCOL OUT evidence gate without emitting a command.
///
/// Selector `0x0010` is directly observed in the write path, but its
/// payload is an aggregate of a 20-byte parameter structure and typed linked
/// descriptors. The selected evidence does not establish enough structure to
/// validate that complete payload, so this function fails closed without
/// inspecting or copying it. Query selectors `0x0020` and `0x0021` are
/// deliberately not accepted for this mutating direction.
///
/// # Errors
///
/// Returns [`ProtocolBuildError::SecurityOutEvidenceIncomplete`] for observed
/// selector `0x0010`, or [`ProtocolBuildError::UnsupportedSecuritySelector`]
/// for every selector not observed in SECURITY PROTOCOL OUT call sites.
pub fn security_out(selector: u16, _payload: &[u8]) -> Result<Command, ProtocolBuildError> {
    Err(validate_security_out_selector(selector))
}

/// Reads the first 128 bytes of the OpenRDX manufacturing record at `0x3E000`.
/// The firmware's fixed TI command requires BOT; callers must compare record bytes.
#[must_use]
pub fn openrdx_manufacturing_record_first() -> Command {
    Command::new(
        [0xe7, 0, 3, 0xe0, 0, 0x80],
        DataDirection::FromDevice,
        vec![0; 128],
    )
}

/// Reads the remaining 128 manufacturing bytes at `0x3E080` over pinned BOT.
#[must_use]
pub fn openrdx_manufacturing_record_second() -> Command {
    Command::new(
        [0xe7, 0, 3, 0xe0, 0x80, 0x80],
        DataDirection::FromDevice,
        vec![0; 128],
    )
}

/// Reads the complete 64-byte OpenRDX operational-state record at `0x3F000`.
/// This is a fixed BOT read, with no caller-selected address, length, or payload.
#[must_use]
pub fn openrdx_operational_state_record() -> Command {
    Command::new(
        [0xe7, 0, 3, 0xf0, 0, 0x40],
        DataDirection::FromDevice,
        vec![0; 64],
    )
}

/// Builds the serial-bound compatibility receiver authorization command.
///
/// # Errors
/// Rejects any serial other than exactly ten printable ASCII bytes.
pub fn compatibility_receiver_authorization(serial: &str) -> Result<Command, ProtocolBuildError> {
    let serial = serial.as_bytes();
    if serial.len() != 10 || !serial.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return Err(ProtocolBuildError::InvalidCompatibilitySerial);
    }
    // Public OpenRDX scripts/rdx_manager_firmware_update.ps1, compatibility setup:
    // the selected adapter's last eight serial bytes are transformed; the first
    // two output bytes remain zero. No caller-supplied mode/address is admitted.
    let key = [0x55, 0xaa, 0x25, 0x46, 0x04, 0xc1, 0x1d, 0xb7];
    let mut authorization = vec![0; 10];
    for (index, key_byte) in key.into_iter().enumerate() {
        authorization[index + 2] = serial[index + 2] ^ key_byte;
    }
    Command::new(
        [0x3b, 2, 0x80, 0, 0, 0, 0, 0, 10, 0],
        DataDirection::ToDevice,
        authorization,
    )
    .with_timeout_ms(15_000)
}

/// Builds only the documented fixed compatibility receiver header-setup command.
#[must_use]
pub fn compatibility_receiver_header_setup() -> Command {
    Command::new(
        [0x3b, 2, 0x82, 2, 0x0f, 0xf8, 0, 0, 2, 0],
        DataDirection::ToDevice,
        vec![0; 2],
    )
    .with_timeout_ms(15_000)
    .expect("documented fixed setup timeout")
}

/// Builds one exact modern RDX firmware WRITE BUFFER command.
///
/// Mode `0x04` requires a non-empty data payload. Mode `0x05` requires an
/// empty payload and creates the no-data finalize command.
///
/// # Errors
///
/// Returns an unsupported-mode or mode/payload error for any command outside
/// the proven modern `0x04`/`0x05` path. Returns a range or payload-size error
/// when offset or length cannot fit the documented 24-bit fields.
pub fn write_buffer(mode: u8, offset: u32, bytes: &[u8]) -> Result<Command, ProtocolBuildError> {
    if !matches!(mode, 0x04 | 0x05) {
        return Err(ProtocolBuildError::UnsupportedWriteBufferMode(mode));
    }
    match (mode, bytes.is_empty()) {
        (0x04, true) => {
            return Err(ProtocolBuildError::WriteBufferPayloadMismatch {
                mode,
                expected: "a non-empty data payload",
                actual: 0,
            });
        }
        (0x05, false) => {
            return Err(ProtocolBuildError::WriteBufferPayloadMismatch {
                mode,
                expected: "an empty finalize payload",
                actual: bytes.len(),
            });
        }
        _ => {}
    }
    if offset > MAX_U24 {
        return Err(ProtocolBuildError::ValueOutOfRange {
            field: "offset",
            value: u64::from(offset),
            maximum: u64::from(MAX_U24),
        });
    }
    if bytes.len() > MAX_U24 as usize {
        return Err(ProtocolBuildError::PayloadTooLarge {
            context: "WRITE BUFFER payload",
            maximum: MAX_U24 as usize,
            actual: bytes.len(),
        });
    }

    let offset = u24_be(offset)?;
    let payload_length = u24_be(bytes.len() as u32)?;
    let direction = if bytes.is_empty() {
        DataDirection::None
    } else {
        DataDirection::ToDevice
    };
    Ok(Command::new(
        [
            0x3B,
            mode,
            0,
            offset[0],
            offset[1],
            offset[2],
            payload_length[0],
            payload_length[1],
            payload_length[2],
            0,
        ],
        direction,
        bytes.to_vec(),
    ))
}

/// Rejects any LOG SENSE page without an exact RDX layout.
fn validate_log_page(page: u8) -> Result<(), ProtocolBuildError> {
    if matches!(page, 0x0D | 0x20 | 0x21) {
        Ok(())
    } else {
        Err(ProtocolBuildError::UnsupportedLogPage(page))
    }
}

/// Rejects any MODE page outside the documented RDX feature/eject set.
fn validate_mode_page(page: u8) -> Result<(), ProtocolBuildError> {
    if matches!(page, 0x31 | 0x33 | 0x34) {
        Ok(())
    } else {
        Err(ProtocolBuildError::UnsupportedModePage(page))
    }
}

/// Returns the minimum body length for one validated MODE page.
fn minimum_mode_page_body_length(page: u8) -> usize {
    match page {
        0x31 => 3,
        0x33 => 2,
        0x34 => 5,
        _ => unreachable!("MODE page is validated before its layout is selected"),
    }
}

/// Returns the stable validation context for one validated MODE page.
fn mode_page_context(page: u8) -> &'static str {
    match page {
        0x31 => "MODE page 0x31 body",
        0x33 => "MODE page 0x33 body",
        0x34 => "MODE page 0x34 body",
        _ => unreachable!("MODE page is validated before its context is selected"),
    }
}

/// Rejects selectors not observed in SECURITY PROTOCOL IN call sites.
fn validate_security_in_selector(selector: u16) -> Result<(), ProtocolBuildError> {
    if matches!(selector, 0x0010 | 0x0020 | 0x0021) {
        Ok(())
    } else {
        Err(ProtocolBuildError::UnsupportedSecuritySelector(selector))
    }
}

/// Returns the direction-specific rejection for a SECURITY PROTOCOL OUT selector.
fn validate_security_out_selector(selector: u16) -> ProtocolBuildError {
    if selector == 0x0010 {
        ProtocolBuildError::SecurityOutEvidenceIncomplete(selector)
    } else {
        ProtocolBuildError::UnsupportedSecuritySelector(selector)
    }
}

/// Requires one declared length to match the actual bounded byte count.
fn require_length(
    context: &'static str,
    declared: usize,
    actual: usize,
) -> Result<(), ProtocolBuildError> {
    if declared == actual {
        Ok(())
    } else {
        Err(ProtocolBuildError::PayloadLengthMismatch {
            context,
            declared,
            actual,
        })
    }
}
