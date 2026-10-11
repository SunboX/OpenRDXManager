// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed conversion from protocol-built packets into native Windows operations.

use super::*;

/// Converts only exact protocol-built commands into the companion's semantic API.
pub(super) fn native_operation(
    packet: &ScsiPassThroughPacket,
) -> Result<rdx_windows_native::ScsiOperation, rdx_windows_native::NativeError> {
    let command = &packet.command;
    let operation = match packet.semantic {
        WindowsSemanticCommand::SelfTest => rdx_windows_native::ScsiOperation::self_test(),
        WindowsSemanticCommand::LedOn => rdx_windows_native::ScsiOperation::led_test(true),
        WindowsSemanticCommand::LedOff => rdx_windows_native::ScsiOperation::led_test(false),
        WindowsSemanticCommand::UnitReset => rdx_windows_native::ScsiOperation::unit_reset(),
        WindowsSemanticCommand::InquiryStandard => {
            rdx_windows_native::ScsiOperation::inquiry_standard()
        }
        WindowsSemanticCommand::InquiryDeviceIdentification => {
            rdx_windows_native::ScsiOperation::inquiry_device_identification()
        }
        WindowsSemanticCommand::InquiryMediaIdentification => {
            rdx_windows_native::ScsiOperation::inquiry_media_identification()
        }
        WindowsSemanticCommand::InquiryMediaDevice => {
            rdx_windows_native::ScsiOperation::inquiry_media_device()
        }
        WindowsSemanticCommand::LogSenseTemperature => {
            rdx_windows_native::ScsiOperation::log_sense_temperature()
        }
        WindowsSemanticCommand::LogSenseDrive => {
            rdx_windows_native::ScsiOperation::log_sense_drive()
        }
        WindowsSemanticCommand::LogSenseCartridge => {
            rdx_windows_native::ScsiOperation::log_sense_cartridge()
        }
        WindowsSemanticCommand::ModeSenseCapabilities => {
            rdx_windows_native::ScsiOperation::mode_sense_capabilities()
        }
        WindowsSemanticCommand::ModeSenseDrive => {
            rdx_windows_native::ScsiOperation::mode_sense_drive()
        }
        WindowsSemanticCommand::ModeSenseSata => {
            rdx_windows_native::ScsiOperation::mode_sense_sata()
        }
        WindowsSemanticCommand::SecurityIn0010 => {
            rdx_windows_native::ScsiOperation::security_in_selector_0010()
        }
        WindowsSemanticCommand::SecurityIn0020 => {
            rdx_windows_native::ScsiOperation::security_in_selector_0020()
        }
        WindowsSemanticCommand::SecurityIn0021 => {
            rdx_windows_native::ScsiOperation::security_in_selector_0021()
        }
        WindowsSemanticCommand::ManufacturingRecordFirst => {
            rdx_windows_native::ScsiOperation::openrdx_manufacturing_record_first()
        }
        WindowsSemanticCommand::ManufacturingRecordSecond => {
            rdx_windows_native::ScsiOperation::openrdx_manufacturing_record_second()
        }
        WindowsSemanticCommand::ManufacturingSector(index) => {
            rdx_windows_native::ScsiOperation::openrdx_manufacturing_sector_chunk(index)?
        }
        WindowsSemanticCommand::OperationalState => {
            rdx_windows_native::ScsiOperation::openrdx_operational_state_record()
        }
        WindowsSemanticCommand::MechanismDiagnostics => {
            rdx_windows_native::ScsiOperation::openrdx_mechanism_diagnostics()
        }
        WindowsSemanticCommand::ManufacturingRestoreCapability => {
            rdx_windows_native::ScsiOperation::openrdx_manufacturing_restore_capability()
        }
        WindowsSemanticCommand::SerialCapability => {
            rdx_windows_native::ScsiOperation::openrdx_serial_capability()
        }
        WindowsSemanticCommand::ManufacturingRestore => {
            rdx_windows_native::ScsiOperation::openrdx_restore_manufacturing(command.data())?
        }
        WindowsSemanticCommand::ModeSelect => rdx_windows_native::ScsiOperation::mode_select(
            command.cdb()[1] & 1 != 0,
            command.data().to_vec(),
        )?,
        WindowsSemanticCommand::FirmwareChunk => {
            let (_, offset) = write_buffer_fields(command)
                .ok_or(rdx_windows_native::NativeError::InvalidRequest)?;
            rdx_windows_native::ScsiOperation::firmware_chunk(offset, command.data().to_vec())?
        }
        WindowsSemanticCommand::FirmwareFinalize => {
            let (_, offset) = write_buffer_fields(command)
                .ok_or(rdx_windows_native::NativeError::InvalidRequest)?;
            rdx_windows_native::ScsiOperation::firmware_finalize(offset)?
        }
        WindowsSemanticCommand::Unknown => {
            return Err(rdx_windows_native::NativeError::InvalidRequest);
        }
    };
    operation.with_timeout_seconds(packet.timeout_seconds())
}
