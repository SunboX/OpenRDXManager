// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed semantic classification for protocol-built macOS commands.

use crate::model::RiskClass;
use crate::protocol::{Command, DataDirection, InquiryPage};

/// Exact semantic identity retained by every validated SCSI task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MacOsSemanticCommand {
    SelfTest,
    LedOn,
    LedOff,
    UnitReset,
    Vendor0283FactoryInfo,
    Vendor0283UsbIdentity,
    CompatibilityReceiverAuthorization,
    CompatibilityReceiverHeaderSetup,
    OpenRdxManufacturingRecordFirst,
    OpenRdxManufacturingRecordSecond,
    OpenRdxOperationalStateRecord,
    OpenRdxManufacturingSectorChunk(u8),
    OpenRdxMechanismDiagnostics,
    OpenRdxManufacturingRestoreCapability,
    OpenRdxSerialCapability,
    OpenRdxRestoreManufacturing,
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
    SecurityIn0010,
    SecurityIn0020,
    SecurityIn0021,
    ModeSelect,
    FirmwareChunk,
    FirmwareFinalize,
    Unknown,
}

impl MacOsSemanticCommand {
    /// Returns the conservative certainty risk attached to this operation.
    pub(super) const fn risk(self) -> RiskClass {
        match self {
            Self::Vendor0283FactoryInfo
            | Self::Vendor0283UsbIdentity
            | Self::OpenRdxManufacturingRecordFirst
            | Self::OpenRdxManufacturingRecordSecond
            | Self::OpenRdxOperationalStateRecord
            | Self::OpenRdxManufacturingSectorChunk(_)
            | Self::OpenRdxMechanismDiagnostics
            | Self::OpenRdxManufacturingRestoreCapability
            | Self::OpenRdxSerialCapability
            | Self::InquiryStandard
            | Self::InquiryDeviceIdentification
            | Self::InquiryMediaIdentification
            | Self::InquiryMediaDevice
            | Self::LogSenseTemperature
            | Self::LogSenseDrive
            | Self::LogSenseCartridge
            | Self::ModeSenseCapabilities
            | Self::ModeSenseDrive
            | Self::ModeSenseSata
            | Self::SecurityIn0010
            | Self::SecurityIn0020
            | Self::SecurityIn0021 => RiskClass::ReadOnly,
            Self::SelfTest | Self::LedOn | Self::LedOff => RiskClass::Routine,
            Self::UnitReset | Self::ModeSelect => RiskClass::Configuration,
            Self::FirmwareChunk
            | Self::FirmwareFinalize
            | Self::CompatibilityReceiverAuthorization
            | Self::CompatibilityReceiverHeaderSetup
            | Self::OpenRdxRestoreManufacturing
            | Self::Unknown => RiskClass::Critical,
        }
    }
}

/// Classifies only exact trusted builder output and fails closed for future commands.
pub(super) fn classify(command: &Command) -> MacOsSemanticCommand {
    use crate::protocol::{inquiry, led_test, log_sense, mode_sense, security_in, self_test};

    if same_wire_command(command, &self_test()) {
        MacOsSemanticCommand::SelfTest
    } else if same_wire_command(command, &led_test(true)) {
        MacOsSemanticCommand::LedOn
    } else if same_wire_command(command, &led_test(false)) {
        MacOsSemanticCommand::LedOff
    } else if same_wire_command(command, &crate::protocol::unit_reset()) {
        MacOsSemanticCommand::UnitReset
    } else if same_wire_command(command, &crate::protocol::vendor_0283_factory_info()) {
        MacOsSemanticCommand::Vendor0283FactoryInfo
    } else if same_wire_command(command, &crate::protocol::vendor_0283_usb_identity()) {
        MacOsSemanticCommand::Vendor0283UsbIdentity
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_record_first(),
    ) {
        MacOsSemanticCommand::OpenRdxManufacturingRecordFirst
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_record_second(),
    ) {
        MacOsSemanticCommand::OpenRdxManufacturingRecordSecond
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_operational_state_record(),
    ) {
        MacOsSemanticCommand::OpenRdxOperationalStateRecord
    } else if let Some(index) = manufacturing_sector_index(command) {
        MacOsSemanticCommand::OpenRdxManufacturingSectorChunk(index)
    } else if same_wire_command(command, &crate::protocol::openrdx_mechanism_diagnostics()) {
        MacOsSemanticCommand::OpenRdxMechanismDiagnostics
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_restore_capability(),
    ) {
        MacOsSemanticCommand::OpenRdxManufacturingRestoreCapability
    } else if same_wire_command(command, &crate::protocol::openrdx_serial_capability()) {
        MacOsSemanticCommand::OpenRdxSerialCapability
    } else if crate::protocol::openrdx_restore_manufacturing(command.data())
        .is_ok_and(|validated| same_wire_command(command, &validated))
    {
        MacOsSemanticCommand::OpenRdxRestoreManufacturing
    } else if is_compatibility_authorization(command) {
        MacOsSemanticCommand::CompatibilityReceiverAuthorization
    } else if same_wire_command(
        command,
        &crate::protocol::compatibility_receiver_header_setup(),
    ) {
        MacOsSemanticCommand::CompatibilityReceiverHeaderSetup
    } else if same_wire_command(command, &inquiry(InquiryPage::Standard)) {
        MacOsSemanticCommand::InquiryStandard
    } else if same_wire_command(command, &inquiry(InquiryPage::DeviceIdentification)) {
        MacOsSemanticCommand::InquiryDeviceIdentification
    } else if same_wire_command(command, &inquiry(InquiryPage::MediaIdentification)) {
        MacOsSemanticCommand::InquiryMediaIdentification
    } else if same_wire_command(command, &inquiry(InquiryPage::MediaDevice)) {
        MacOsSemanticCommand::InquiryMediaDevice
    } else if same_wire_command(command, &log_sense(0x0D).expect("proven LOG page")) {
        MacOsSemanticCommand::LogSenseTemperature
    } else if same_wire_command(command, &log_sense(0x20).expect("proven LOG page")) {
        MacOsSemanticCommand::LogSenseDrive
    } else if same_wire_command(command, &log_sense(0x21).expect("proven LOG page")) {
        MacOsSemanticCommand::LogSenseCartridge
    } else if same_wire_command(command, &mode_sense(0x31).expect("proven MODE page")) {
        MacOsSemanticCommand::ModeSenseCapabilities
    } else if same_wire_command(command, &mode_sense(0x33).expect("proven MODE page")) {
        MacOsSemanticCommand::ModeSenseDrive
    } else if same_wire_command(command, &mode_sense(0x34).expect("proven MODE page")) {
        MacOsSemanticCommand::ModeSenseSata
    } else if same_wire_command(command, &security_in(0x0010).expect("proven selector")) {
        MacOsSemanticCommand::SecurityIn0010
    } else if same_wire_command(command, &security_in(0x0020).expect("proven selector")) {
        MacOsSemanticCommand::SecurityIn0020
    } else if same_wire_command(command, &security_in(0x0021).expect("proven selector")) {
        MacOsSemanticCommand::SecurityIn0021
    } else if is_mode_select(command) {
        MacOsSemanticCommand::ModeSelect
    } else if let Some((mode, _)) = write_buffer_fields(command) {
        match mode {
            0x04 => MacOsSemanticCommand::FirmwareChunk,
            0x05 => MacOsSemanticCommand::FirmwareFinalize,
            _ => MacOsSemanticCommand::Unknown,
        }
    } else {
        MacOsSemanticCommand::Unknown
    }
}

/// Recovers only an index whose complete wire command matches a fixed sector builder.
fn manufacturing_sector_index(command: &Command) -> Option<u8> {
    (0..32).find(|index| {
        crate::protocol::openrdx_manufacturing_sector_chunk(*index)
            .is_ok_and(|expected| same_wire_command(command, &expected))
    })
}

/// Recognizes only the documented serial-derived authorization at its fixed buffer.
fn is_compatibility_authorization(command: &Command) -> bool {
    let data = command.data();
    let key = [0x55, 0xaa, 0x25, 0x46, 0x04, 0xc1, 0x1d, 0xb7];
    command.cdb() == [0x3b, 2, 0x80, 0, 0, 0, 0, 0, 10, 0]
        && command.direction() == DataDirection::ToDevice
        && data.len() == 10
        && data[..2] == [0, 0]
        && data[2..]
            .iter()
            .zip(key)
            .all(|(byte, key_byte)| (0x20..=0x7e).contains(&(byte ^ key_byte)))
}

/// Compares immutable wire fields while allowing a bounded timeout override.
fn same_wire_command(left: &Command, right: &Command) -> bool {
    left.cdb() == right.cdb()
        && left.direction() == right.direction()
        && left.data() == right.data()
}

/// Recognizes the exact MODE SELECT shape emitted by the trusted builder.
fn is_mode_select(command: &Command) -> bool {
    let cdb = command.cdb();
    cdb.len() == 10
        && cdb[0] == 0x55
        && matches!(cdb[1], 0x10 | 0x11)
        && cdb[2..7] == [0; 5]
        && cdb[9] == 0
        && command.direction() == DataDirection::ToDevice
        && usize::from(u16::from_be_bytes([cdb[7], cdb[8]])) == command.data().len()
}

/// Recognizes the exact bounded mode-4/mode-5 WRITE BUFFER family.
pub(super) fn write_buffer_fields(command: &Command) -> Option<(u8, u32)> {
    let cdb = command.cdb();
    if cdb.len() != 10
        || cdb[0] != 0x3B
        || !matches!(cdb[1], 0x04 | 0x05)
        || cdb[2] != 0
        || cdb[9] != 0
    {
        return None;
    }
    let offset = u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]);
    let declared = usize::try_from(u32::from_be_bytes([0, cdb[6], cdb[7], cdb[8]])).ok()?;
    let valid = match cdb[1] {
        0x04 => {
            command.direction() == DataDirection::ToDevice
                && !command.data().is_empty()
                && declared == command.data().len()
        }
        0x05 => {
            command.direction() == DataDirection::None && command.data().is_empty() && declared == 0
        }
        _ => false,
    };
    valid.then_some((cdb[1], offset))
}

/// Converts an exact classified packet into the companion's closed operation API.
#[cfg(target_os = "macos")]
pub(super) fn native_operation(
    packet: &super::MacOsScsiTask,
) -> Result<rdx_macos_native::ScsiOperation, rdx_macos_native::NativeError> {
    let command = &packet.command;
    let operation = match packet.semantic {
        MacOsSemanticCommand::SelfTest => rdx_macos_native::ScsiOperation::self_test(),
        MacOsSemanticCommand::LedOn => rdx_macos_native::ScsiOperation::led_test(true),
        MacOsSemanticCommand::LedOff => rdx_macos_native::ScsiOperation::led_test(false),
        MacOsSemanticCommand::UnitReset => rdx_macos_native::ScsiOperation::unit_reset(),
        MacOsSemanticCommand::Vendor0283FactoryInfo => {
            rdx_macos_native::ScsiOperation::vendor_0283_factory_info()
        }
        MacOsSemanticCommand::Vendor0283UsbIdentity => {
            rdx_macos_native::ScsiOperation::vendor_0283_usb_identity()
        }
        MacOsSemanticCommand::OpenRdxManufacturingRecordFirst => {
            rdx_macos_native::ScsiOperation::openrdx_manufacturing_record_first()
        }
        MacOsSemanticCommand::OpenRdxManufacturingRecordSecond => {
            rdx_macos_native::ScsiOperation::openrdx_manufacturing_record_second()
        }
        MacOsSemanticCommand::OpenRdxOperationalStateRecord => {
            rdx_macos_native::ScsiOperation::openrdx_operational_state_record()
        }
        MacOsSemanticCommand::OpenRdxManufacturingSectorChunk(index) => {
            rdx_macos_native::ScsiOperation::openrdx_manufacturing_sector_chunk(index)?
        }
        MacOsSemanticCommand::OpenRdxMechanismDiagnostics => {
            rdx_macos_native::ScsiOperation::openrdx_mechanism_diagnostics()
        }
        MacOsSemanticCommand::OpenRdxManufacturingRestoreCapability => {
            rdx_macos_native::ScsiOperation::openrdx_manufacturing_restore_capability()
        }
        MacOsSemanticCommand::OpenRdxSerialCapability => {
            rdx_macos_native::ScsiOperation::openrdx_serial_capability()
        }
        MacOsSemanticCommand::OpenRdxRestoreManufacturing => {
            rdx_macos_native::ScsiOperation::openrdx_restore_manufacturing(command.data())?
        }
        MacOsSemanticCommand::CompatibilityReceiverAuthorization => {
            rdx_macos_native::ScsiOperation::compatibility_receiver_authorization(command.data())?
        }
        MacOsSemanticCommand::CompatibilityReceiverHeaderSetup => {
            rdx_macos_native::ScsiOperation::compatibility_receiver_header_setup()
        }
        MacOsSemanticCommand::InquiryStandard => {
            rdx_macos_native::ScsiOperation::inquiry_standard()
        }
        MacOsSemanticCommand::InquiryDeviceIdentification => {
            rdx_macos_native::ScsiOperation::inquiry_device_identification()
        }
        MacOsSemanticCommand::InquiryMediaIdentification => {
            rdx_macos_native::ScsiOperation::inquiry_media_identification()
        }
        MacOsSemanticCommand::InquiryMediaDevice => {
            rdx_macos_native::ScsiOperation::inquiry_media_device()
        }
        MacOsSemanticCommand::LogSenseTemperature => {
            rdx_macos_native::ScsiOperation::log_sense_temperature()
        }
        MacOsSemanticCommand::LogSenseDrive => rdx_macos_native::ScsiOperation::log_sense_drive(),
        MacOsSemanticCommand::LogSenseCartridge => {
            rdx_macos_native::ScsiOperation::log_sense_cartridge()
        }
        MacOsSemanticCommand::ModeSenseCapabilities => {
            rdx_macos_native::ScsiOperation::mode_sense_capabilities()
        }
        MacOsSemanticCommand::ModeSenseDrive => rdx_macos_native::ScsiOperation::mode_sense_drive(),
        MacOsSemanticCommand::ModeSenseSata => rdx_macos_native::ScsiOperation::mode_sense_sata(),
        MacOsSemanticCommand::SecurityIn0010 => {
            rdx_macos_native::ScsiOperation::security_in_selector_0010()
        }
        MacOsSemanticCommand::SecurityIn0020 => {
            rdx_macos_native::ScsiOperation::security_in_selector_0020()
        }
        MacOsSemanticCommand::SecurityIn0021 => {
            rdx_macos_native::ScsiOperation::security_in_selector_0021()
        }
        MacOsSemanticCommand::ModeSelect => rdx_macos_native::ScsiOperation::mode_select(
            command.cdb()[1] & 1 != 0,
            command.data().to_vec(),
        )?,
        MacOsSemanticCommand::FirmwareChunk => {
            let (_, offset) = write_buffer_fields(command)
                .ok_or(rdx_macos_native::NativeError::InvalidRequest)?;
            rdx_macos_native::ScsiOperation::firmware_chunk(offset, command.data().to_vec())?
        }
        MacOsSemanticCommand::FirmwareFinalize => {
            let (_, offset) = write_buffer_fields(command)
                .ok_or(rdx_macos_native::NativeError::InvalidRequest)?;
            rdx_macos_native::ScsiOperation::firmware_finalize(offset)?
        }
        MacOsSemanticCommand::Unknown => {
            return Err(rdx_macos_native::NativeError::InvalidRequest);
        }
    };
    operation.with_timeout_ms(packet.timeout_ms)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Restore payloads retain critical risk while probes and sector reads remain read-only.
    #[test]
    fn manufacturing_restore_semantics_dispatch_fixed_native_operations() {
        let mut data = vec![0; 528];
        data[..8].copy_from_slice(b"RDXMFG01");
        data[272..276].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        for (command, native, risk) in [
            (
                crate::protocol::openrdx_manufacturing_sector_chunk(31).unwrap(),
                rdx_macos_native::ScsiOperation::openrdx_manufacturing_sector_chunk(31).unwrap(),
                RiskClass::ReadOnly,
            ),
            (
                crate::protocol::openrdx_mechanism_diagnostics(),
                rdx_macos_native::ScsiOperation::openrdx_mechanism_diagnostics(),
                RiskClass::ReadOnly,
            ),
            (
                crate::protocol::openrdx_manufacturing_restore_capability(),
                rdx_macos_native::ScsiOperation::openrdx_manufacturing_restore_capability(),
                RiskClass::ReadOnly,
            ),
            (
                crate::protocol::openrdx_restore_manufacturing(&data).unwrap(),
                rdx_macos_native::ScsiOperation::openrdx_restore_manufacturing(&data).unwrap(),
                RiskClass::Critical,
            ),
        ] {
            let packet = super::super::build_scsi_task(&command).unwrap();
            assert_eq!(packet.semantic.risk(), risk);
            assert_eq!(native_operation(&packet), Ok(native));
        }
    }

    /// Fixed record reads retain exact semantic identity through native conversion.
    #[test]
    fn openrdx_record_reads_dispatch_only_closed_native_constructors() {
        for (command, expected) in [
            (
                crate::protocol::openrdx_manufacturing_record_first(),
                rdx_macos_native::ScsiOperation::openrdx_manufacturing_record_first(),
            ),
            (
                crate::protocol::openrdx_manufacturing_record_second(),
                rdx_macos_native::ScsiOperation::openrdx_manufacturing_record_second(),
            ),
            (
                crate::protocol::openrdx_operational_state_record(),
                rdx_macos_native::ScsiOperation::openrdx_operational_state_record(),
            ),
        ] {
            let packet = super::super::build_scsi_task(&command).unwrap();
            assert_eq!(native_operation(&packet), Ok(expected));
        }
    }

    /// Semantic conversion preserves the two closed mutations and fixed timeouts.
    #[test]
    fn compatibility_setup_dispatches_only_closed_native_constructors() {
        let authorization =
            crate::protocol::compatibility_receiver_authorization("0123456789").unwrap();
        let packet = super::super::build_scsi_task(&authorization).unwrap();
        assert_eq!(
            native_operation(&packet),
            rdx_macos_native::ScsiOperation::compatibility_receiver_authorization(&[
                0, 0, 0x67, 0x99, 0x11, 0x73, 0x32, 0xf6, 0x25, 0x8e
            ])
        );
        let packet =
            super::super::build_scsi_task(&crate::protocol::compatibility_receiver_header_setup())
                .unwrap();
        assert_eq!(
            native_operation(&packet),
            Ok(rdx_macos_native::ScsiOperation::compatibility_receiver_header_setup())
        );
    }
}
