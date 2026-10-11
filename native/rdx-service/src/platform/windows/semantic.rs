// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed semantic classification for protocol-built Windows commands.

use crate::model::RiskClass;
use crate::protocol::{Command, DataDirection, InquiryPage};

/// Exact semantic identity retained by every validated SPTI packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowsSemanticCommand {
    SelfTest,
    LedOn,
    LedOff,
    UnitReset,
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
    ManufacturingRecordFirst,
    ManufacturingRecordSecond,
    ManufacturingSector(u8),
    OperationalState,
    MechanismDiagnostics,
    ManufacturingRestoreCapability,
    SerialCapability,
    ManufacturingRestore,
    ModeSelect,
    FirmwareChunk,
    FirmwareFinalize,
    Unknown,
}

impl WindowsSemanticCommand {
    /// Returns the conservative risk bound attached to this semantic command.
    pub(super) const fn risk(self) -> RiskClass {
        match self {
            Self::InquiryStandard
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
            | Self::SecurityIn0021
            | Self::ManufacturingRecordFirst
            | Self::ManufacturingRecordSecond
            | Self::ManufacturingSector(_)
            | Self::OperationalState
            | Self::MechanismDiagnostics
            | Self::ManufacturingRestoreCapability
            | Self::SerialCapability => RiskClass::ReadOnly,
            Self::SelfTest | Self::LedOn | Self::LedOff => RiskClass::Routine,
            Self::UnitReset | Self::ModeSelect => RiskClass::Configuration,
            Self::FirmwareChunk
            | Self::FirmwareFinalize
            | Self::ManufacturingRestore
            | Self::Unknown => RiskClass::Critical,
        }
    }
}

/// Classifies only exact command-builder output and fails closed for future commands.
pub(super) fn classify(command: &Command) -> WindowsSemanticCommand {
    use crate::protocol::{inquiry, led_test, log_sense, mode_sense, security_in, self_test};

    if same_wire_command(command, &self_test()) {
        WindowsSemanticCommand::SelfTest
    } else if same_wire_command(command, &led_test(true)) {
        WindowsSemanticCommand::LedOn
    } else if same_wire_command(command, &led_test(false)) {
        WindowsSemanticCommand::LedOff
    } else if same_wire_command(command, &crate::protocol::unit_reset()) {
        WindowsSemanticCommand::UnitReset
    } else if same_wire_command(command, &inquiry(InquiryPage::Standard)) {
        WindowsSemanticCommand::InquiryStandard
    } else if same_wire_command(command, &inquiry(InquiryPage::DeviceIdentification)) {
        WindowsSemanticCommand::InquiryDeviceIdentification
    } else if same_wire_command(command, &inquiry(InquiryPage::MediaIdentification)) {
        WindowsSemanticCommand::InquiryMediaIdentification
    } else if same_wire_command(command, &inquiry(InquiryPage::MediaDevice)) {
        WindowsSemanticCommand::InquiryMediaDevice
    } else if same_wire_command(command, &log_sense(0x0D).expect("proven LOG page")) {
        WindowsSemanticCommand::LogSenseTemperature
    } else if same_wire_command(command, &log_sense(0x20).expect("proven LOG page")) {
        WindowsSemanticCommand::LogSenseDrive
    } else if same_wire_command(command, &log_sense(0x21).expect("proven LOG page")) {
        WindowsSemanticCommand::LogSenseCartridge
    } else if same_wire_command(command, &mode_sense(0x31).expect("proven MODE page")) {
        WindowsSemanticCommand::ModeSenseCapabilities
    } else if same_wire_command(command, &mode_sense(0x33).expect("proven MODE page")) {
        WindowsSemanticCommand::ModeSenseDrive
    } else if same_wire_command(command, &mode_sense(0x34).expect("proven MODE page")) {
        WindowsSemanticCommand::ModeSenseSata
    } else if same_wire_command(
        command,
        &security_in(0x0010).expect("proven security selector"),
    ) {
        WindowsSemanticCommand::SecurityIn0010
    } else if same_wire_command(
        command,
        &security_in(0x0020).expect("proven security selector"),
    ) {
        WindowsSemanticCommand::SecurityIn0020
    } else if same_wire_command(
        command,
        &security_in(0x0021).expect("proven security selector"),
    ) {
        WindowsSemanticCommand::SecurityIn0021
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_record_first(),
    ) {
        WindowsSemanticCommand::ManufacturingRecordFirst
    } else if same_wire_command(
        command,
        &crate::protocol::openrdx_manufacturing_record_second(),
    ) {
        WindowsSemanticCommand::ManufacturingRecordSecond
    } else if let Some(operation) = preservation_command(command) {
        operation
    } else if is_mode_select(command) {
        WindowsSemanticCommand::ModeSelect
    } else if let Some((mode, _)) = write_buffer_fields(command) {
        match mode {
            0x04 => WindowsSemanticCommand::FirmwareChunk,
            0x05 => WindowsSemanticCommand::FirmwareFinalize,
            _ => WindowsSemanticCommand::Unknown,
        }
    } else {
        WindowsSemanticCommand::Unknown
    }
}

/// Classifies only the receiver's fixed preservation reads and validated restore.
fn preservation_command(command: &Command) -> Option<WindowsSemanticCommand> {
    use crate::protocol::*;
    for (expected, semantic) in [
        (
            openrdx_operational_state_record(),
            WindowsSemanticCommand::OperationalState,
        ),
        (
            openrdx_mechanism_diagnostics(),
            WindowsSemanticCommand::MechanismDiagnostics,
        ),
        (
            openrdx_manufacturing_restore_capability(),
            WindowsSemanticCommand::ManufacturingRestoreCapability,
        ),
        (
            openrdx_serial_capability(),
            WindowsSemanticCommand::SerialCapability,
        ),
    ] {
        if same_wire_command(command, &expected) {
            return Some(semantic);
        }
    }
    for index in 2..32 {
        if same_wire_command(
            command,
            &openrdx_manufacturing_sector_chunk(index).expect("bounded sector chunk"),
        ) {
            return Some(WindowsSemanticCommand::ManufacturingSector(index));
        }
    }
    if let Ok(expected) = openrdx_restore_manufacturing(command.data())
        && same_wire_command(command, &expected)
    {
        return Some(WindowsSemanticCommand::ManufacturingRestore);
    }
    None
}

/// Compares immutable command wire fields while allowing a bounded timeout override.
fn same_wire_command(left: &Command, right: &Command) -> bool {
    left.cdb() == right.cdb()
        && left.direction() == right.direction()
        && left.data() == right.data()
}

/// Recognizes only the exact MODE SELECT CDB shape emitted by the trusted builder.
pub(super) fn is_mode_select(command: &Command) -> bool {
    let cdb = command.cdb();
    cdb.len() == 10
        && cdb[0] == 0x55
        && matches!(cdb[1], 0x10 | 0x11)
        && cdb[2..7] == [0; 5]
        && cdb[9] == 0
        && command.direction() == DataDirection::ToDevice
        && usize::from(u16::from_be_bytes([cdb[7], cdb[8]])) == command.data().len()
}

/// Recognizes the exact bounded mode-4/mode-5 WRITE BUFFER CDB family.
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
