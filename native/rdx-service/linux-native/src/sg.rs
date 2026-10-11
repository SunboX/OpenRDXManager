// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed semantic SCSI operations and Linux SG v3 ABI types.

use std::ffi::c_void;

use crate::NativeError;
#[cfg(test)]
mod firmware_read_tests;

const MAX_CDB_LENGTH: usize = 16;
const MAX_TRANSFER_LENGTH: usize = 0x1000;
/// Fixed Linux request-sense capacity.
pub(crate) const MAX_SENSE_LENGTH: usize = 0xFC;
const MAX_TIMEOUT_MS: u32 = 300_000;
const DEFAULT_TIMEOUT_MS: u32 = 30_000;
const MAX_U24: u32 = 0x00FF_FFFF;

/// Pointer-free exact requirements translated into Linux `open(2)` flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SgOpenRequirements {
    read_write: bool,
    exclusive: bool,
    nonblocking: bool,
    close_on_exec: bool,
    no_follow: bool,
}

impl SgOpenRequirements {
    /// Returns whether the SG descriptor requires read/write access.
    #[must_use]
    pub const fn read_write(self) -> bool {
        self.read_write
    }

    /// Returns whether the SG descriptor requires exclusive ownership.
    #[must_use]
    pub const fn exclusive(self) -> bool {
        self.exclusive
    }

    /// Returns whether open must avoid blocking on device state.
    #[must_use]
    pub const fn nonblocking(self) -> bool {
        self.nonblocking
    }

    /// Returns whether the descriptor must close across execution.
    #[must_use]
    pub const fn close_on_exec(self) -> bool {
        self.close_on_exec
    }

    /// Returns whether the final device-node component must not be followed.
    #[must_use]
    pub const fn no_follow(self) -> bool {
        self.no_follow
    }
}

/// Returns the complete least-authority SG descriptor open policy.
#[must_use]
pub const fn sg_open_requirements() -> SgOpenRequirements {
    SgOpenRequirements {
        read_write: true,
        exclusive: true,
        nonblocking: true,
        close_on_exec: true,
        no_follow: true,
    }
}

/// Direction of one validated SCSI data phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataDirection {
    None,
    FromDevice,
    ToDevice,
}

/// Public semantic operation with no caller-supplied CDB surface.
pub struct ScsiOperation {
    kind: ScsiOperationKind,
    timeout_ms: u32,
}

enum ScsiOperationKind {
    TestUnitReady,
    SelfTest,
    LedTest(bool),
    UnitReset,
    EjectMedia,
    InquiryStandard,
    InquiryDeviceIdentification,
    InquiryVpd { page: u8, allocation: u16 },
    LogSense(u8),
    ModeSense(u8),
    ModeSelect { save_pages: bool, data: Vec<u8> },
    SecurityIn(u16),
    OpenRdxManufacturingRecordFirst,
    OpenRdxManufacturingRecordSecond,
    OpenRdxManufacturingRestoreCapability,
    OpenRdxSerialCapability,
    FirmwareChunk { offset: u32, data: Vec<u8> },
    FirmwareFinalize { offset: u32 },
}

impl ScsiOperation {
    /// Creates standard no-data TEST UNIT READY to check current media presence.
    #[must_use]
    pub const fn test_unit_ready() -> Self {
        Self::new(ScsiOperationKind::TestUnitReady)
    }

    /// Creates the exact no-data SEND DIAGNOSTIC self-test operation.
    #[must_use]
    pub const fn self_test() -> Self {
        Self::new(ScsiOperationKind::SelfTest)
    }

    /// Creates the exact bounded LED diagnostic operation.
    #[must_use]
    pub const fn led_test(on: bool) -> Self {
        Self::new(ScsiOperationKind::LedTest(on))
    }

    /// Creates the exact no-data RDX unit-reset operation.
    #[must_use]
    pub const fn unit_reset() -> Self {
        Self::new(ScsiOperationKind::UnitReset)
    }

    /// Creates standard START STOP UNIT with LOEJ set and START clear.
    #[must_use]
    pub const fn eject_media() -> Self {
        Self::new(ScsiOperationKind::EjectMedia)
    }

    /// Creates standard INQUIRY with the fixed OpenRDX allocation length.
    #[must_use]
    pub const fn inquiry_standard() -> Self {
        Self::new(ScsiOperationKind::InquiryStandard)
    }

    /// Creates device-identification VPD INQUIRY page `0x83`.
    #[must_use]
    pub const fn inquiry_device_identification() -> Self {
        Self::new(ScsiOperationKind::InquiryDeviceIdentification)
    }

    /// Creates cartridge-identification VPD INQUIRY page `0xC0`.
    #[must_use]
    pub const fn inquiry_media_identification() -> Self {
        Self::new(ScsiOperationKind::InquiryVpd {
            page: 0xC0,
            allocation: 0x00FE,
        })
    }

    /// Creates ATA identify-device cartridge VPD INQUIRY page `0xC2`.
    #[must_use]
    pub const fn inquiry_media_device() -> Self {
        Self::new(ScsiOperationKind::InquiryVpd {
            page: 0xC2,
            allocation: 0x0200,
        })
    }

    /// Creates standard temperature LOG SENSE page `0x0D`.
    #[must_use]
    pub const fn log_sense_temperature() -> Self {
        Self::new(ScsiOperationKind::LogSense(0x0D))
    }

    /// Creates LOG SENSE page `0x20`.
    #[must_use]
    pub const fn log_sense_drive() -> Self {
        Self::new(ScsiOperationKind::LogSense(0x20))
    }

    /// Creates LOG SENSE page `0x21`.
    #[must_use]
    pub const fn log_sense_cartridge() -> Self {
        Self::new(ScsiOperationKind::LogSense(0x21))
    }

    /// Creates MODE SENSE page `0x31`.
    #[must_use]
    pub const fn mode_sense_capabilities() -> Self {
        Self::new(ScsiOperationKind::ModeSense(0x31))
    }

    /// Creates MODE SENSE page `0x33`.
    #[must_use]
    pub const fn mode_sense_drive() -> Self {
        Self::new(ScsiOperationKind::ModeSense(0x33))
    }

    /// Creates MODE SENSE page `0x34`.
    #[must_use]
    pub const fn mode_sense_sata() -> Self {
        Self::new(ScsiOperationKind::ModeSense(0x34))
    }

    /// Creates a structurally bounded MODE SELECT for an RDX page.
    ///
    /// # Errors
    ///
    /// Rejects oversized, truncated, inconsistent, or unsupported mode pages.
    pub fn mode_select(save_pages: bool, data: Vec<u8>) -> Result<Self, NativeError> {
        validate_mode_select(&data)?;
        Ok(Self::new(ScsiOperationKind::ModeSelect {
            save_pages,
            data,
        }))
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0010`.
    #[must_use]
    pub const fn security_in_selector_0010() -> Self {
        Self::new(ScsiOperationKind::SecurityIn(0x0010))
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0020`.
    #[must_use]
    pub const fn security_in_selector_0020() -> Self {
        Self::new(ScsiOperationKind::SecurityIn(0x0020))
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0021`.
    #[must_use]
    pub const fn security_in_selector_0021() -> Self {
        Self::new(ScsiOperationKind::SecurityIn(0x0021))
    }

    /// Reads exactly the first 128 factory-record bytes at the fixed SPI address.
    #[must_use]
    pub const fn openrdx_manufacturing_record_first() -> Self {
        Self::new(ScsiOperationKind::OpenRdxManufacturingRecordFirst)
    }

    /// Reads exactly the remaining 128 factory-record bytes at the fixed SPI address.
    #[must_use]
    pub const fn openrdx_manufacturing_record_second() -> Self {
        Self::new(ScsiOperationKind::OpenRdxManufacturingRecordSecond)
    }

    /// Queries manufacturing command support without a payload or any write.
    #[must_use]
    pub const fn openrdx_manufacturing_restore_capability() -> Self {
        Self::new(ScsiOperationKind::OpenRdxManufacturingRestoreCapability)
    }

    /// Queries the released receiver's serial interlock without changing its latch.
    #[must_use]
    pub const fn openrdx_serial_capability() -> Self {
        Self::new(ScsiOperationKind::OpenRdxSerialCapability)
    }

    /// Creates one bounded mode-4 firmware WRITE BUFFER transfer.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized payloads and offsets outside 24 bits.
    pub fn firmware_chunk(offset: u32, data: Vec<u8>) -> Result<Self, NativeError> {
        if offset > MAX_U24 || data.is_empty() || data.len() > MAX_TRANSFER_LENGTH {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self::new(ScsiOperationKind::FirmwareChunk { offset, data }))
    }

    /// Creates one no-data mode-5 firmware WRITE BUFFER finalize operation.
    ///
    /// # Errors
    ///
    /// Rejects an image length outside the exact 24-bit field.
    pub fn firmware_finalize(offset: u32) -> Result<Self, NativeError> {
        if offset > MAX_U24 {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self::new(ScsiOperationKind::FirmwareFinalize { offset }))
    }

    /// Replaces the fixed timeout with another bounded millisecond value.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above five minutes.
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Result<Self, NativeError> {
        if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(NativeError::InvalidRequest);
        }
        self.timeout_ms = timeout_ms;
        Ok(self)
    }

    /// Creates one semantic operation with the default timeout.
    const fn new(kind: ScsiOperationKind) -> Self {
        Self {
            kind,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Encodes this closed operation into a bounded internal SG request.
    pub(crate) fn into_request(self) -> Result<ScsiRequest, NativeError> {
        let (cdb, direction, data) = encode_operation(self.kind);
        ScsiRequest::new(&cdb, direction, data, self.timeout_ms, MAX_SENSE_LENGTH)
    }
}

impl std::fmt::Debug for ScsiOperation {
    /// Redacts operation fields and payload bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScsiOperation(<private>)")
    }
}

/// Fully bounded request copied into the Linux-only ioctl layer.
pub(crate) struct ScsiRequest {
    cdb: [u8; MAX_CDB_LENGTH],
    cdb_length: u8,
    direction: DataDirection,
    data: Vec<u8>,
    timeout_ms: u32,
    sense_capacity: u8,
}

impl ScsiRequest {
    /// Independently enforces every FFI bound.
    fn new(
        cdb: &[u8],
        direction: DataDirection,
        data: Vec<u8>,
        timeout_ms: u32,
        sense_capacity: usize,
    ) -> Result<Self, NativeError> {
        let direction_is_consistent = match direction {
            DataDirection::None => data.is_empty(),
            DataDirection::FromDevice | DataDirection::ToDevice => !data.is_empty(),
        };
        if cdb.is_empty()
            || cdb.len() > MAX_CDB_LENGTH
            || data.len() > MAX_TRANSFER_LENGTH
            || !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms)
            || sense_capacity > MAX_SENSE_LENGTH
            || !direction_is_consistent
        {
            return Err(NativeError::InvalidRequest);
        }
        let mut copied = [0_u8; MAX_CDB_LENGTH];
        copied[..cdb.len()].copy_from_slice(cdb);
        Ok(Self {
            cdb: copied,
            cdb_length: cdb.len() as u8,
            direction,
            data,
            timeout_ms,
            sense_capacity: sense_capacity as u8,
        })
    }

    /// Returns only initialized CDB bytes.
    pub(crate) fn cdb(&self) -> &[u8] {
        &self.cdb[..usize::from(self.cdb_length)]
    }

    /// Returns the internal data direction.
    pub(crate) const fn direction(&self) -> DataDirection {
        self.direction
    }

    /// Cartridge VPD may remain cached after removal and requires fresh readiness.
    pub(crate) fn needs_cartridge_readiness(&self) -> bool {
        matches!(self.cdb(), [0x12, 0x01, 0xC0 | 0xC2, ..])
    }

    /// Returns the owned transfer storage.
    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns mutable transfer storage for native data-in completion.
    #[cfg(target_os = "linux")]
    pub(crate) fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Moves transfer storage out after the synchronous ioctl.
    #[cfg(target_os = "linux")]
    pub(crate) fn take_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }

    /// Returns the exact timeout in milliseconds.
    pub(crate) const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// Returns the fixed sense capacity.
    pub(crate) const fn sense_capacity(&self) -> usize {
        self.sense_capacity as usize
    }
}

/// Builds one fixed vendor VPD INQUIRY used only for current cartridge identity.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn media_identity_request(page: u8) -> Result<ScsiRequest, NativeError> {
    let allocation = match page {
        0xC0 => 0x00FE_u16,
        // The payload is the complete 512-byte ATA identify block, preceded
        // by a four-byte VPD header. Identity validation requires both.
        0xC2 => 4 + 512_u16,
        _ => return Err(NativeError::InvalidRequest),
    };
    ScsiRequest::new(
        &[0x12, 1, page, (allocation >> 8) as u8, allocation as u8, 0],
        DataDirection::FromDevice,
        vec![0; usize::from(allocation)],
        DEFAULT_TIMEOUT_MS,
        MAX_SENSE_LENGTH,
    )
}

/// Extracts bounded serial fields from both actively queried RDX cartridge pages.
pub(crate) fn media_identity_material_from_vpd(
    c0: &[u8],
    c2: &[u8],
) -> Result<Vec<u8>, NativeError> {
    let cartridge = vpd_ascii_field(c0, 0xC0, 0x42, 20)?;
    let medium = vpd_ascii_field(c2, 0xC2, 0x18, 20)?;
    let mut material = Vec::with_capacity(2 + cartridge.len() + medium.len());
    material.push(cartridge.len() as u8);
    material.extend_from_slice(cartridge);
    material.push(medium.len() as u8);
    material.extend_from_slice(medium);
    Ok(material)
}

/// Validates one VPD response header and returns a trimmed printable ASCII field.
fn vpd_ascii_field(
    page: &[u8],
    expected_page: u8,
    offset: usize,
    length: usize,
) -> Result<&[u8], NativeError> {
    if page.len() < 4 || page[1] != expected_page {
        return Err(NativeError::EvidenceIncomplete);
    }
    let payload_length = usize::from(u16::from_be_bytes([page[2], page[3]]));
    let response_length = payload_length
        .checked_add(4)
        .ok_or(NativeError::ResourceLimit)?;
    let end = offset
        .checked_add(length)
        .ok_or(NativeError::ResourceLimit)?;
    if response_length > page.len() || end > response_length {
        return Err(NativeError::EvidenceIncomplete);
    }
    let field = &page[offset..end];
    if !field
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    let start = field
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(field.len());
    let end = field
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(start, |index| index + 1);
    if start == end {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(&field[start..end])
}

/// Linux SG v3 ioctl header with the exact public C ABI layout.
#[repr(C)]
pub(crate) struct SgIoHeader {
    pub(crate) interface_id: i32,
    pub(crate) dxfer_direction: i32,
    pub(crate) cmd_len: u8,
    pub(crate) max_sense_len: u8,
    pub(crate) iovec_count: u16,
    pub(crate) dxfer_len: u32,
    pub(crate) dxferp: *mut c_void,
    pub(crate) cmdp: *mut u8,
    pub(crate) sensep: *mut u8,
    pub(crate) timeout: u32,
    pub(crate) flags: u32,
    pub(crate) pack_id: i32,
    pub(crate) user_ptr: *mut c_void,
    pub(crate) status: u8,
    pub(crate) masked_status: u8,
    pub(crate) message_status: u8,
    pub(crate) sense_len_written: u8,
    pub(crate) host_status: u16,
    pub(crate) driver_status: u16,
    pub(crate) residual: i32,
    pub(crate) duration: u32,
    pub(crate) info: u32,
}

/// Pointer-free completion copied from one synchronous SG ioctl.
pub enum Completion {
    /// Validation or allocation failed before `ioctl` was invoked.
    NotAttempted(NativeError),
    /// `ioctl` was invoked but returned no usable SG completion.
    AttemptedError(NativeError),
    /// The kernel returned a complete bounded header and owned buffers.
    Device {
        /// Raw SCSI status.
        status: u8,
        /// Shifted/masked SCSI status.
        masked_status: u8,
        /// SCSI message status.
        message_status: u8,
        /// Host adapter status.
        host_status: u16,
        /// Low-level driver status.
        driver_status: u16,
        /// SG result/direct-I/O flags.
        info: u32,
        /// Signed Linux residual.
        residual: i32,
        /// Owned bounded transfer data.
        data: Vec<u8>,
        /// Exact reported request-sense length.
        sense_reported_length: usize,
        /// Copied bounded request-sense bytes.
        sense: Vec<u8>,
    },
}

impl std::fmt::Debug for Completion {
    /// Formats only sanitized status and lengths.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAttempted(error) => {
                formatter.debug_tuple("NotAttempted").field(error).finish()
            }
            Self::AttemptedError(error) => formatter
                .debug_tuple("AttemptedError")
                .field(error)
                .finish(),
            Self::Device {
                status,
                masked_status,
                message_status,
                host_status,
                driver_status,
                info,
                residual,
                data,
                sense_reported_length,
                sense,
            } => formatter
                .debug_struct("Device")
                .field("status", status)
                .field("masked_status", masked_status)
                .field("message_status", message_status)
                .field("host_status", host_status)
                .field("driver_status", driver_status)
                .field("info", info)
                .field("residual", residual)
                .field("data_length", &data.len())
                .field("sense_reported_length", sense_reported_length)
                .field("sense_copied_length", &sense.len())
                .finish_non_exhaustive(),
        }
    }
}

/// Encodes one closed semantic operation into its exact CDB and transfer storage.
fn encode_operation(operation: ScsiOperationKind) -> (Vec<u8>, DataDirection, Vec<u8>) {
    match operation {
        ScsiOperationKind::TestUnitReady => (vec![0; 6], DataDirection::None, Vec::new()),
        ScsiOperationKind::SelfTest => (
            vec![0x1D, 0x04, 0, 0, 0, 0],
            DataDirection::None,
            Vec::new(),
        ),
        ScsiOperationKind::LedTest(on) => {
            let mut data = vec![0x80, 0, 0, 4];
            data.extend_from_slice(&u32::from(!on).to_be_bytes());
            (vec![0x1D, 0, 0, 0, 8, 0], DataDirection::ToDevice, data)
        }
        ScsiOperationKind::UnitReset => (
            vec![0x1D, 0x05, 0, 0, 0, 0],
            DataDirection::None,
            Vec::new(),
        ),
        ScsiOperationKind::EjectMedia => (
            vec![0x1B, 0, 0, 0, 0x02, 0],
            DataDirection::None,
            Vec::new(),
        ),
        ScsiOperationKind::InquiryStandard => (
            vec![0x12, 0, 0, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::InquiryDeviceIdentification => (
            vec![0x12, 1, 0x83, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::InquiryVpd { page, allocation } => {
            let [high, low] = allocation.to_be_bytes();
            (
                vec![0x12, 1, page, high, low, 0],
                DataDirection::FromDevice,
                vec![0; usize::from(allocation)],
            )
        }
        ScsiOperationKind::LogSense(page) => (
            vec![0x4D, 0, page, 0, 0, 0, 0, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::ModeSense(page) => (
            vec![0x5A, 0, page, 0, 0, 0, 0, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::ModeSelect { save_pages, data } => {
            let length = u16::try_from(data.len()).expect("validated MODE SELECT length");
            let [high, low] = length.to_be_bytes();
            (
                vec![
                    0x55,
                    0x10 | u8::from(save_pages),
                    0,
                    0,
                    0,
                    0,
                    0,
                    high,
                    low,
                    0,
                ],
                DataDirection::ToDevice,
                data,
            )
        }
        ScsiOperationKind::SecurityIn(selector) => {
            let [high, low] = selector.to_be_bytes();
            (
                vec![0xA2, 0x20, high, low, 0, 0, 0, 0, 0x10, 0, 0, 0],
                DataDirection::FromDevice,
                vec![0; 0x1000],
            )
        }
        ScsiOperationKind::OpenRdxManufacturingRecordFirst => (
            vec![0xe7, 0, 3, 0xe0, 0, 0x80],
            DataDirection::FromDevice,
            vec![0; 128],
        ),
        ScsiOperationKind::OpenRdxManufacturingRecordSecond => (
            vec![0xe7, 0, 3, 0xe0, 0x80, 0x80],
            DataDirection::FromDevice,
            vec![0; 128],
        ),
        // These exact mode-2 commands are no-data queries, despite their WRITE
        // BUFFER opcode. Neither a restore payload nor arbitrary mode-2 is exposed.
        ScsiOperationKind::OpenRdxManufacturingRestoreCapability => (
            vec![0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0],
            DataDirection::None,
            Vec::new(),
        ),
        ScsiOperationKind::OpenRdxSerialCapability => (
            vec![0x3b, 2, 0x53, 0, 0, 1, 0, 0, 0, 0],
            DataDirection::None,
            Vec::new(),
        ),
        ScsiOperationKind::FirmwareChunk { offset, data } => {
            let offset = offset.to_be_bytes();
            let length = (data.len() as u32).to_be_bytes();
            (
                vec![
                    0x3B, 0x04, 0, offset[1], offset[2], offset[3], length[1], length[2],
                    length[3], 0,
                ],
                DataDirection::ToDevice,
                data,
            )
        }
        ScsiOperationKind::FirmwareFinalize { offset } => {
            let offset = offset.to_be_bytes();
            (
                vec![0x3B, 0x05, 0, offset[1], offset[2], offset[3], 0, 0, 0, 0],
                DataDirection::None,
                Vec::new(),
            )
        }
    }
}

/// Validates one MODE SELECT parameter list independently.
fn validate_mode_select(data: &[u8]) -> Result<(), NativeError> {
    if data.len() < 10 || data.len() > u16::MAX as usize {
        return Err(NativeError::InvalidRequest);
    }
    let block_length = usize::from(u16::from_be_bytes([data[6], data[7]]));
    let page_offset = 8_usize
        .checked_add(block_length)
        .ok_or(NativeError::InvalidRequest)?;
    if page_offset + 2 > data.len() {
        return Err(NativeError::InvalidRequest);
    }
    let page = data[page_offset] & 0x3F;
    let page_length = usize::from(data[page_offset + 1]);
    if data[page_offset] & 0x40 != 0
        || !matches!(page, 0x31 | 0x33 | 0x34)
        || page_offset + 2 + page_length != data.len()
    {
        return Err(NativeError::InvalidRequest);
    }
    Ok(())
}
