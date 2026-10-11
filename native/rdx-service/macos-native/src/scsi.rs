// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed, independently validated SCSI operations accepted by the C bridge.

use crate::NativeError;
use crate::ffi;

const DEFAULT_TIMEOUT_MS: u32 = 30_000;
const MAX_TIMEOUT_MS: u32 = 300_000;
const MAX_U24: u32 = 0x00FF_FFFF;

/// Enables bounded stage/numeric-code stderr diagnostics for this process only.
///
/// Normal service and CLI callers remain silent by default. The isolated
/// snapshot collector opts in before acquisition; no device operation occurs.
pub fn enable_acquisition_diagnostics() {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this no-argument call only enables a process-local atomic flag.
        unsafe { ffi::rdx_macos_enable_acquisition_diagnostics() };
    }
}

/// Public semantic SCSI operation with no caller-supplied CDB surface.
///
/// Only exact OpenRDX operations can construct this type. Variable payloads,
/// offsets, and timeouts are independently bounded before crossing FFI.
#[derive(Eq, PartialEq)]
pub struct ScsiOperation {
    kind: ScsiOperationKind,
    timeout_ms: u32,
}

#[derive(Eq, PartialEq)]
enum ScsiOperationKind {
    SelfTest,
    LedTest(bool),
    UnitReset,
    EjectMedia,
    InquiryStandard,
    InquiryDeviceIdentification,
    InquiryMediaIdentification,
    InquiryMediaDevice,
    LogSenseTemperature,
    LogSenseDrive,
    LogSenseCartridge,
    ModeSenseCapabilities,
    ModeSenseDrive,
    ModeSenseSata,
    Vendor0283FactoryInfo,
    Vendor0283UsbIdentity,
    CompatibilityReceiverAuthorization { data: [u8; 10] },
    CompatibilityReceiverHeaderSetup,
    OpenRdxManufacturingRecordFirst,
    OpenRdxManufacturingRecordSecond,
    OpenRdxOperationalStateRecord,
    OpenRdxManufacturingSectorChunk(u8),
    OpenRdxSerialCapability,
    OpenRdxMechanismDiagnostics,
    OpenRdxSetSerial { data: Vec<u8> },
    OpenRdxManufacturingRestoreCapability,
    OpenRdxRestoreManufacturing { data: zeroize::Zeroizing<Vec<u8>> },
    SecurityIn0010,
    SecurityIn0020,
    SecurityIn0021,
    ModeSelect { save_pages: bool, data: Vec<u8> },
    FirmwareChunk { offset: u32, data: Vec<u8> },
    FirmwareFinalize { offset: u32 },
}

impl ScsiOperation {
    /// Probes only the fixed manufacturing restore capability without changing flash.
    #[must_use]
    pub const fn openrdx_manufacturing_restore_capability() -> Self {
        Self::new(ScsiOperationKind::OpenRdxManufacturingRestoreCapability)
    }

    /// Builds the fixed manufacturing compare-and-replace operation.
    ///
    /// # Errors
    /// Rejects malformed framing or a desired record with an invalid checksum.
    pub fn openrdx_restore_manufacturing(data: &[u8]) -> Result<Self, NativeError> {
        if !crate::manufacturing_contract::payload_is_valid(data) {
            return Err(NativeError::InvalidRequest);
        }
        Self::new(ScsiOperationKind::OpenRdxRestoreManufacturing {
            data: zeroize::Zeroizing::new(data.to_vec()),
        })
        .with_timeout_ms(120_000)
    }

    /// Reads one fixed 128-byte chunk of the manufacturing sector; no address is accepted.
    ///
    /// # Errors
    /// Rejects indices outside the complete sector's 0..32 chunk range.
    pub fn openrdx_manufacturing_sector_chunk(index: u8) -> Result<Self, NativeError> {
        if index >= 32 {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self::new(
            ScsiOperationKind::OpenRdxManufacturingSectorChunk(index),
        ))
    }

    /// Reads only the fixed 128-byte RDX mechanism diagnostic frame.
    #[must_use]
    pub const fn openrdx_mechanism_diagnostics() -> Self {
        Self::new(ScsiOperationKind::OpenRdxMechanismDiagnostics)
    }

    /// Probes the serial protocol without a payload, flash write, or reset.
    #[must_use]
    pub const fn openrdx_serial_capability() -> Self {
        Self::new(ScsiOperationKind::OpenRdxSerialCapability)
    }

    /// Builds only the fixed compare-and-set serial command after validating its record.
    ///
    /// # Errors
    /// Rejects malformed framing, flags, serial digits, or inconsistent record state.
    pub fn openrdx_set_serial(data: Vec<u8>) -> Result<Self, NativeError> {
        if !crate::serial_contract::payload_is_valid(&data) {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self::new(ScsiOperationKind::OpenRdxSetSerial { data }))
    }

    /// Reads exactly the first 128 manufacturing-record bytes through a BOT lease.
    #[must_use]
    pub const fn openrdx_manufacturing_record_first() -> Self {
        Self::new(ScsiOperationKind::OpenRdxManufacturingRecordFirst)
    }

    /// Reads exactly the second 128 manufacturing-record bytes through a BOT lease.
    #[must_use]
    pub const fn openrdx_manufacturing_record_second() -> Self {
        Self::new(ScsiOperationKind::OpenRdxManufacturingRecordSecond)
    }

    /// Reads exactly the 64 operational-state bytes through a BOT lease.
    #[must_use]
    pub const fn openrdx_operational_state_record() -> Self {
        Self::new(ScsiOperationKind::OpenRdxOperationalStateRecord)
    }

    /// Accepts only the documented ten-byte, zero-prefixed authorization framing.
    ///
    /// # Errors
    /// Rejects malformed framing or a non-printable decoded serial suffix.
    pub fn compatibility_receiver_authorization(authorization: &[u8]) -> Result<Self, NativeError> {
        if !compatibility_authorization_is_valid(authorization) {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self {
            kind: ScsiOperationKind::CompatibilityReceiverAuthorization {
                data: authorization
                    .try_into()
                    .expect("validated ten-byte authorization"),
            },
            timeout_ms: 15_000,
        })
    }

    /// Creates only the fixed compatibility header setup, never an arbitrary write.
    #[must_use]
    pub const fn compatibility_receiver_header_setup() -> Self {
        Self {
            kind: ScsiOperationKind::CompatibilityReceiverHeaderSetup,
            timeout_ms: 15_000,
        }
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

    /// Creates standard INQUIRY with the fixed allocation length.
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
        Self::new(ScsiOperationKind::InquiryMediaIdentification)
    }

    /// Creates ATA identify-device cartridge VPD INQUIRY page `0xC2`.
    #[must_use]
    pub const fn inquiry_media_device() -> Self {
        Self::new(ScsiOperationKind::InquiryMediaDevice)
    }

    /// Creates standard temperature LOG SENSE page `0x0D`.
    #[must_use]
    pub const fn log_sense_temperature() -> Self {
        Self::new(ScsiOperationKind::LogSenseTemperature)
    }

    /// Creates drive LOG SENSE page `0x20`.
    #[must_use]
    pub const fn log_sense_drive() -> Self {
        Self::new(ScsiOperationKind::LogSenseDrive)
    }

    /// Creates cartridge LOG SENSE page `0x21`.
    #[must_use]
    pub const fn log_sense_cartridge() -> Self {
        Self::new(ScsiOperationKind::LogSenseCartridge)
    }

    /// Creates MODE SENSE page `0x31`.
    #[must_use]
    pub const fn mode_sense_capabilities() -> Self {
        Self::new(ScsiOperationKind::ModeSenseCapabilities)
    }

    /// Creates MODE SENSE page `0x33`.
    #[must_use]
    pub const fn mode_sense_drive() -> Self {
        Self::new(ScsiOperationKind::ModeSenseDrive)
    }

    /// Creates MODE SENSE page `0x34`.
    #[must_use]
    pub const fn mode_sense_sata() -> Self {
        Self::new(ScsiOperationKind::ModeSenseSata)
    }

    /// Reads only the fixed vendor-0283 factory-info buffer (mode 2, ID 2, 172 bytes).
    #[must_use]
    pub const fn vendor_0283_factory_info() -> Self {
        Self::new(ScsiOperationKind::Vendor0283FactoryInfo)
    }

    /// Reads only the fixed vendor-0283 USB-identity buffer (mode 2, ID 10, 32 bytes).
    #[must_use]
    pub const fn vendor_0283_usb_identity() -> Self {
        Self::new(ScsiOperationKind::Vendor0283UsbIdentity)
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0010`.
    #[must_use]
    pub const fn security_in_selector_0010() -> Self {
        Self::new(ScsiOperationKind::SecurityIn0010)
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0020`.
    #[must_use]
    pub const fn security_in_selector_0020() -> Self {
        Self::new(ScsiOperationKind::SecurityIn0020)
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0021`.
    #[must_use]
    pub const fn security_in_selector_0021() -> Self {
        Self::new(ScsiOperationKind::SecurityIn0021)
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

    /// Creates one bounded mode-4 firmware WRITE BUFFER transfer.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized payloads and offsets outside 24 bits.
    pub fn firmware_chunk(offset: u32, data: Vec<u8>) -> Result<Self, NativeError> {
        if offset > MAX_U24 || data.is_empty() || data.len() > ffi::MAX_TRANSFER_BYTES {
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
    /// Rejects zero and values above five minutes before native dispatch.
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Result<Self, NativeError> {
        if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(NativeError::InvalidRequest);
        }
        self.timeout_ms = timeout_ms;
        Ok(self)
    }

    const fn new(kind: ScsiOperationKind) -> Self {
        Self {
            kind,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    pub(crate) fn into_request(self) -> ffi::ScsiRequest {
        let mut request = ffi::ScsiRequest {
            abi_version: ffi::ABI_VERSION,
            timeout_ms: self.timeout_ms,
            ..ffi::ScsiRequest::default()
        };
        match self.kind {
            ScsiOperationKind::SelfTest => request.operation = 1,
            ScsiOperationKind::LedTest(true) => request.operation = 2,
            ScsiOperationKind::LedTest(false) => request.operation = 3,
            ScsiOperationKind::UnitReset => request.operation = 4,
            ScsiOperationKind::InquiryStandard => request.operation = 5,
            ScsiOperationKind::InquiryDeviceIdentification => request.operation = 6,
            ScsiOperationKind::LogSenseDrive => request.operation = 7,
            ScsiOperationKind::LogSenseCartridge => request.operation = 8,
            ScsiOperationKind::ModeSenseCapabilities => request.operation = 9,
            ScsiOperationKind::ModeSenseDrive => request.operation = 10,
            ScsiOperationKind::ModeSenseSata => request.operation = 11,
            ScsiOperationKind::SecurityIn0010 => request.operation = 12,
            ScsiOperationKind::SecurityIn0020 => request.operation = 13,
            ScsiOperationKind::SecurityIn0021 => request.operation = 14,
            ScsiOperationKind::ModeSelect { save_pages, data } => {
                request.operation = 15;
                request.save_pages = u8::from(save_pages);
                request.data_length = data.len() as u32;
                request.data[..data.len()].copy_from_slice(&data);
            }
            ScsiOperationKind::FirmwareChunk { offset, data } => {
                request.operation = 16;
                request.offset = offset;
                request.data_length = data.len() as u32;
                request.data[..data.len()].copy_from_slice(&data);
            }
            ScsiOperationKind::FirmwareFinalize { offset } => {
                request.operation = 17;
                request.offset = offset;
            }
            ScsiOperationKind::InquiryMediaIdentification => request.operation = 18,
            ScsiOperationKind::InquiryMediaDevice => request.operation = 19,
            ScsiOperationKind::LogSenseTemperature => request.operation = 20,
            ScsiOperationKind::EjectMedia => request.operation = 21,
            ScsiOperationKind::Vendor0283FactoryInfo => request.operation = 22,
            ScsiOperationKind::Vendor0283UsbIdentity => request.operation = 23,
            ScsiOperationKind::CompatibilityReceiverAuthorization { data } => {
                request.operation = 24;
                request.data_length = 10;
                request.data[..10].copy_from_slice(&data);
            }
            ScsiOperationKind::CompatibilityReceiverHeaderSetup => request.operation = 25,
            ScsiOperationKind::OpenRdxManufacturingRecordFirst => request.operation = 26,
            ScsiOperationKind::OpenRdxManufacturingRecordSecond => request.operation = 27,
            ScsiOperationKind::OpenRdxOperationalStateRecord => request.operation = 28,
            ScsiOperationKind::OpenRdxManufacturingSectorChunk(index) => {
                request.operation = 29;
                request.offset = u32::from(index);
            }
            ScsiOperationKind::OpenRdxSerialCapability => request.operation = 30,
            ScsiOperationKind::OpenRdxMechanismDiagnostics => request.operation = 32,
            ScsiOperationKind::OpenRdxManufacturingRestoreCapability => request.operation = 33,
            ScsiOperationKind::OpenRdxRestoreManufacturing { data } => {
                request.operation = 34;
                request.data_length = 528;
                request.data[..528].copy_from_slice(&data);
            }
            ScsiOperationKind::OpenRdxSetSerial { data } => {
                request.operation = 31;
                request.data_length = 280;
                request.data[..280].copy_from_slice(&data);
            }
        }
        request
    }
}

impl std::fmt::Debug for ScsiOperation {
    /// Redacts semantic identity, timeout, offset, and payload bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScsiOperation(<private>)")
    }
}

/// Independently validates the sole documented authorization payload shape.
pub(crate) fn compatibility_authorization_is_valid(data: &[u8]) -> bool {
    let key = [0x55, 0xaa, 0x25, 0x46, 0x04, 0xc1, 0x1d, 0xb7];
    data.len() == 10
        && data[..2] == [0, 0]
        && data[2..]
            .iter()
            .zip(key)
            .all(|(byte, key_byte)| (0x20..=0x7e).contains(&(byte ^ key_byte)))
}

/// Validates the variable MODE SELECT payload independently of the parent.
fn validate_mode_select(data: &[u8]) -> Result<(), NativeError> {
    if data.len() < 10 || data.len() > ffi::MAX_TRANSFER_BYTES || data[..3] != [0, 0, 0] {
        return Err(NativeError::InvalidRequest);
    }
    let descriptor_length = usize::from(u16::from_be_bytes([data[6], data[7]]));
    let page_offset = 8_usize
        .checked_add(descriptor_length)
        .ok_or(NativeError::InvalidRequest)?;
    if page_offset + 2 > data.len() {
        return Err(NativeError::InvalidRequest);
    }
    let page_header = data[page_offset];
    let minimum_body = match page_header & 0x3F {
        0x31 => 3,
        0x33 => 2,
        0x34 => 5,
        _ => return Err(NativeError::InvalidRequest),
    };
    if page_header & 0x40 != 0 {
        return Err(NativeError::InvalidRequest);
    }
    let body_length = usize::from(data[page_offset + 1]);
    let expected_length = page_offset
        .checked_add(2)
        .and_then(|value| value.checked_add(body_length))
        .ok_or(NativeError::InvalidRequest)?;
    if body_length < minimum_body || expected_length != data.len() {
        return Err(NativeError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ScsiOperation;

    /// Fixed record selectors carry no variable address, length, or payload across FFI.
    #[test]
    fn openrdx_record_reads_are_fixed_native_operations() {
        for (operation, expected) in [
            (ScsiOperation::openrdx_manufacturing_record_first(), 26),
            (ScsiOperation::openrdx_manufacturing_record_second(), 27),
            (ScsiOperation::openrdx_operational_state_record(), 28),
        ] {
            let request = operation.into_request();
            assert_eq!(request.operation, expected);
            assert_eq!(request.data_length, 0);
            assert_eq!(request.offset, 0);
            assert_eq!(request.save_pages, 0);
            assert_eq!(request.timeout_ms, 30_000);
        }
    }

    /// The final C boundary checks exact wire bytes and rejects non-BOT leases without I/O.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn openrdx_record_c_wire_contract_and_bot_guard_are_exact() {
        unsafe extern "C" {
            fn rdx_macos_test_openrdx_record_scsi_contract() -> bool;
        }
        // SAFETY: the hook inspects stack-only records and never dereferences its BOT sentinel.
        assert!(unsafe { rdx_macos_test_openrdx_record_scsi_contract() });
    }

    /// The native boundary independently bounds the serial-derived authorization.
    #[test]
    fn compatibility_setup_native_requests_are_closed() {
        let authorization = [0, 0, 0x67, 0x99, 0x11, 0x73, 0x32, 0xf6, 0x25, 0x8e];
        let request = ScsiOperation::compatibility_receiver_authorization(&authorization)
            .unwrap()
            .into_request();
        assert_eq!(request.operation, 24);
        assert_eq!(request.data_length, 10);
        assert_eq!(&request.data[..10], &authorization);
        assert_eq!(request.offset, 0);
        assert_eq!(request.save_pages, 0);
        assert_eq!(request.timeout_ms, 15_000);
        for bad in [&authorization[..9], &[0; 11], &[1; 10]] {
            assert!(ScsiOperation::compatibility_receiver_authorization(bad).is_err());
        }
        let key = [0x55, 0xaa, 0x25, 0x46, 0x04, 0xc1, 0x1d, 0xb7];
        for (index, key_byte) in key.into_iter().enumerate() {
            let mut invalid = authorization;
            invalid[index + 2] = key_byte ^ 0x1f;
            assert!(ScsiOperation::compatibility_receiver_authorization(&invalid).is_err());
        }
        let header = ScsiOperation::compatibility_receiver_header_setup().into_request();
        assert_eq!(header.operation, 25);
        assert_eq!(header.data_length, 0);
        assert_eq!(header.offset, 0);
        assert_eq!(header.save_pages, 0);
        assert_eq!(header.timeout_ms, 15_000);
    }

    /// Native C builds only the two documented requests without accessing hardware.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn compatibility_setup_c_wire_contract_is_exact() {
        unsafe extern "C" {
            fn rdx_macos_test_compatibility_setup_scsi_contract() -> bool;
        }
        // SAFETY: the test hook uses stack-only requests and never opens a device.
        assert!(unsafe { rdx_macos_test_compatibility_setup_scsi_contract() });
    }

    /// Physical eject remains a closed no-data START STOP UNIT semantic request.
    #[test]
    fn eject_media_uses_the_closed_native_operation() {
        let request = ScsiOperation::eject_media().into_request();

        assert_eq!(request.operation, 21);
        assert_eq!(request.data_length, 0);
        assert_eq!(request.offset, 0);
        assert_eq!(request.save_pages, 0);
    }

    /// Factory reads never accept variable buffers, offsets, IDs, or payloads.
    #[test]
    fn factory_snapshot_reads_are_fixed_native_operations() {
        for (operation, expected) in [
            (ScsiOperation::vendor_0283_factory_info(), 22),
            (ScsiOperation::vendor_0283_usb_identity(), 23),
        ] {
            let request = operation.into_request();
            assert_eq!(request.operation, expected);
            assert_eq!(request.data_length, 0);
            assert_eq!(request.offset, 0);
            assert_eq!(request.save_pages, 0);
        }
    }

    /// The C boundary independently proves fixed data-in CDBs and rejects mutation.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn factory_snapshot_c_wire_contract_is_exact() {
        // SAFETY: this test hook accepts no pointers and uses local fixed records.
        assert!(unsafe { crate::ffi::rdx_macos_test_factory_snapshot_scsi_contract() });
    }

    /// Acquisition diagnostics remain opt-in and cannot print arbitrary strings.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn factory_snapshot_acquisition_diagnostics_are_bounded() {
        // SAFETY: this hook formats local fixed values without opening hardware.
        assert!(unsafe { crate::ffi::rdx_macos_test_acquisition_diagnostics_contract() });
    }
}
