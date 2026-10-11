// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed semantic classification for protocol-built Linux commands.

use crate::model::RiskClass;
use crate::protocol::{Command, DataDirection, InquiryPage};

/// Exact semantic identity retained by every validated `SG_IO` packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxSemanticCommand {
    SelfTest,
    LedOn,
    LedOff,
    UnitReset,
    OpenRdxManufacturingRecordFirst,
    OpenRdxManufacturingRecordSecond,
    OpenRdxManufacturingRestoreCapability,
    OpenRdxSerialCapability,
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

impl LinuxSemanticCommand {
    /// Returns the conservative risk bound attached to this semantic command.
    pub(super) const fn risk(self) -> RiskClass {
        match self {
            Self::OpenRdxManufacturingRecordFirst
            | Self::OpenRdxManufacturingRecordSecond
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
            Self::FirmwareChunk | Self::FirmwareFinalize | Self::Unknown => RiskClass::Critical,
        }
    }
}

/// Classifies only exact command-builder output and fails closed for future commands.
pub(super) fn classify(command: &Command) -> LinuxSemanticCommand {
    use crate::protocol::{inquiry, led_test, log_sense, mode_sense, security_in, self_test};

    if same_wire_command(command, &self_test()) {
        LinuxSemanticCommand::SelfTest
    } else if same_wire_command(command, &led_test(true)) {
        LinuxSemanticCommand::LedOn
    } else if same_wire_command(command, &led_test(false)) {
        LinuxSemanticCommand::LedOff
    } else if same_wire_command(command, &crate::protocol::unit_reset()) {
        LinuxSemanticCommand::UnitReset
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_record_first(),
    ) {
        LinuxSemanticCommand::OpenRdxManufacturingRecordFirst
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_record_second(),
    ) {
        LinuxSemanticCommand::OpenRdxManufacturingRecordSecond
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_restore_capability(),
    ) {
        LinuxSemanticCommand::OpenRdxManufacturingRestoreCapability
    } else if same_wire_command(command, &crate::protocol::openrdx_serial_capability()) {
        LinuxSemanticCommand::OpenRdxSerialCapability
    } else if same_wire_command(command, &inquiry(InquiryPage::Standard)) {
        LinuxSemanticCommand::InquiryStandard
    } else if same_wire_command(command, &inquiry(InquiryPage::DeviceIdentification)) {
        LinuxSemanticCommand::InquiryDeviceIdentification
    } else if same_wire_command(command, &inquiry(InquiryPage::MediaIdentification)) {
        LinuxSemanticCommand::InquiryMediaIdentification
    } else if same_wire_command(command, &inquiry(InquiryPage::MediaDevice)) {
        LinuxSemanticCommand::InquiryMediaDevice
    } else if same_wire_command(command, &log_sense(0x0D).expect("proven LOG page")) {
        LinuxSemanticCommand::LogSenseTemperature
    } else if same_wire_command(command, &log_sense(0x20).expect("proven LOG page")) {
        LinuxSemanticCommand::LogSenseDrive
    } else if same_wire_command(command, &log_sense(0x21).expect("proven LOG page")) {
        LinuxSemanticCommand::LogSenseCartridge
    } else if same_wire_command(command, &mode_sense(0x31).expect("proven MODE page")) {
        LinuxSemanticCommand::ModeSenseCapabilities
    } else if same_wire_command(command, &mode_sense(0x33).expect("proven MODE page")) {
        LinuxSemanticCommand::ModeSenseDrive
    } else if same_wire_command(command, &mode_sense(0x34).expect("proven MODE page")) {
        LinuxSemanticCommand::ModeSenseSata
    } else if same_wire_command(
        command,
        &security_in(0x0010).expect("proven security selector"),
    ) {
        LinuxSemanticCommand::SecurityIn0010
    } else if same_wire_command(
        command,
        &security_in(0x0020).expect("proven security selector"),
    ) {
        LinuxSemanticCommand::SecurityIn0020
    } else if same_wire_command(
        command,
        &security_in(0x0021).expect("proven security selector"),
    ) {
        LinuxSemanticCommand::SecurityIn0021
    } else if is_mode_select(command) {
        LinuxSemanticCommand::ModeSelect
    } else if let Some((mode, _)) = write_buffer_fields(command) {
        match mode {
            0x04 => LinuxSemanticCommand::FirmwareChunk,
            0x05 => LinuxSemanticCommand::FirmwareFinalize,
            _ => LinuxSemanticCommand::Unknown,
        }
    } else {
        LinuxSemanticCommand::Unknown
    }
}

/// Compares immutable command wire fields while allowing a bounded timeout override.
fn same_wire_command(left: &Command, right: &Command) -> bool {
    left.cdb() == right.cdb()
        && left.direction() == right.direction()
        && left.data() == right.data()
}

/// Recognizes only the exact MODE SELECT shape emitted by the trusted builder.
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
    let declared_length = usize::try_from(u32::from_be_bytes([0, cdb[6], cdb[7], cdb[8]])).ok()?;
    let shape_matches = match cdb[1] {
        0x04 => {
            command.direction() == DataDirection::ToDevice
                && !command.data().is_empty()
                && declared_length == command.data().len()
        }
        0x05 => {
            command.direction() == DataDirection::None
                && command.data().is_empty()
                && declared_length == 0
        }
        _ => false,
    };
    shape_matches.then_some((cdb[1], offset))
}
