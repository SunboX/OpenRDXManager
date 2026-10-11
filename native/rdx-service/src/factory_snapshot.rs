#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-target, read-only collection of migration source and restoration evidence.
//!
//! Non-macOS builds retain the parser and pure validation implementation for
//! portable tests, while the public entry point fails before native access.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::protocol::{RdxFeaturePage, parse_log_page};

mod diagnostics;
use diagnostics::{NativeFailureKind, SnapshotFailure, SnapshotStage};

#[cfg(target_os = "macos")]
mod native;

/// Fixed diagnostic classes that never contain device bytes or private paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotError {
    InvalidArguments,
    TargetMissing,
    TargetAmbiguous,
    UnsupportedFirmware,
    ReadbackRevisionMismatch,
    IdentityChanged,
    IncompleteResponse,
    DeviceBusy,
    Native(NativeFailureKind),
    OutputUnavailable,
    #[cfg(not(target_os = "macos"))]
    UnsupportedPlatform,
}

impl SnapshotError {
    /// Returns only a fixed diagnostic suitable for ordinary process output.
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "snapshot-invalid-arguments",
            Self::TargetMissing => "snapshot-target-missing",
            Self::TargetAmbiguous => "snapshot-target-ambiguous",
            Self::UnsupportedFirmware => "snapshot-requires-vendor-0283",
            Self::ReadbackRevisionMismatch => "snapshot-readback-requires-0107",
            Self::IdentityChanged => "snapshot-identity-changed",
            Self::IncompleteResponse => "snapshot-response-incomplete",
            Self::DeviceBusy => "snapshot-device-busy",
            Self::Native(NativeFailureKind::AccessDenied) => "snapshot-read-access-denied",
            Self::Native(NativeFailureKind::Busy) => "snapshot-device-busy",
            Self::Native(NativeFailureKind::DeviceRemoved) => "snapshot-identity-changed",
            Self::Native(_) => "snapshot-read-transport-unavailable",
            Self::OutputUnavailable => "snapshot-private-output-unavailable",
            #[cfg(not(target_os = "macos"))]
            Self::UnsupportedPlatform => "snapshot-platform-unsupported",
        }
    }
}

/// The collector can issue only these five fixed read operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotRead {
    Inquiry,
    FactoryInfo,
    UsbIdentity,
    DriveLog,
    ModeSense,
}

/// Fixed capture purposes keep vendor input and postboot observations distinct.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SnapshotPurpose {
    #[default]
    MigrationSource,
    RestorationReadback,
}

impl SnapshotPurpose {
    /// Returns the only accepted reported revision for this explicit purpose.
    const fn revision(self) -> &'static str {
        match self {
            Self::MigrationSource => "0283",
            Self::RestorationReadback => "0107",
        }
    }

    /// Labels readback separately so it can never be reused as vendor source input.
    const fn kind(self) -> &'static str {
        match self {
            Self::MigrationSource => "openrdx-vendor-0283-semantic-snapshot",
            Self::RestorationReadback => "openrdx-0107-restoration-readback",
        }
    }
}

/// Observed properties of the selected SCSI service's actual USB ancestor.
#[derive(Clone, Copy)]
struct UsbIdentity {
    location_id: u32,
    vendor_id: u16,
    product_id: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotDevice<'a> {
    usb_serial: &'a str,
    inquiry_revision: &'static str,
    usb_location_id: u32,
    usb_vendor_id: u16,
    usb_product_id: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawResponses {
    drive_log_hex: String,
    mode_sense_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot<'a> {
    schema_version: u8,
    kind: &'static str,
    device: SnapshotDevice<'a>,
    inquiry_hex: String,
    factory_info_hex: String,
    usb_identity_hex: String,
    load_count: u32,
    operation_mode: u8,
    raw_responses: RawResponses,
}

struct Arguments {
    usb_serial: String,
    output: PathBuf,
    purpose: SnapshotPurpose,
}

/// Runs the isolated research collector and exits without exposing private data.
///
/// `--usb-serial <exact twelve digits>` and `--output <absolute new path>` are
/// required. Optional `--readback` selects a separate revision-0107 observation;
/// it does not establish firmware-image identity or installation success.
/// No native discovery occurs for invalid arguments or existing
/// output. On macOS, the process retains the exact read lease until exit: the
/// USB capture fallback can terminate its owner during explicit destruction.
/// No firmware, mode, reset, eject, or unmount operation is available here.
pub fn run_cli_and_exit(arguments: impl Iterator<Item = OsString>) -> ! {
    let arguments = match parse_arguments(arguments) {
        Ok(arguments) => arguments,
        Err(error) => finish_and_exit(Err(error.at(SnapshotStage::Arguments))),
    };
    if let Err(error) = ensure_new_output(&arguments.output) {
        finish_and_exit(Err(error.at(SnapshotStage::OutputPreflight)));
    }
    #[cfg(target_os = "macos")]
    native::run(arguments);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = arguments;
        finish_and_exit(Err(
            SnapshotError::UnsupportedPlatform.at(SnapshotStage::Platform)
        ));
    }
}

/// Flushes a fixed outcome before OS teardown releases the native capture lease.
fn finish_and_exit(result: Result<(), SnapshotFailure>) -> ! {
    let exit = match result {
        Ok(()) => {
            let mut output = std::io::stdout().lock();
            if output
                .write_all(b"{\"status\":\"ok\",\"command\":\"factory-snapshot\"}\n")
                .is_ok()
                && output.flush().is_ok()
            {
                0
            } else {
                1
            }
        }
        Err(error) => {
            let mut output = std::io::stderr().lock();
            let _ = error.write_to(&mut output);
            1
        }
    };
    std::process::exit(exit)
}

/// Parses only the closed explicit-target command syntax, without device I/O.
fn parse_arguments(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<Arguments, SnapshotError> {
    let mut usb_serial = None;
    let mut output = None;
    let mut purpose = SnapshotPurpose::MigrationSource;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--readback") if purpose == SnapshotPurpose::MigrationSource => {
                purpose = SnapshotPurpose::RestorationReadback;
            }
            Some("--usb-serial") if usb_serial.is_none() => {
                let serial = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or(SnapshotError::InvalidArguments)?;
                validate_serial(&serial)?;
                usb_serial = Some(serial);
            }
            Some("--output") if output.is_none() => {
                let path = PathBuf::from(arguments.next().ok_or(SnapshotError::InvalidArguments)?);
                if !path.is_absolute() || path.file_name().is_none() {
                    return Err(SnapshotError::InvalidArguments);
                }
                output = Some(path);
            }
            _ => return Err(SnapshotError::InvalidArguments),
        }
    }
    Ok(Arguments {
        usb_serial: usb_serial.ok_or(SnapshotError::InvalidArguments)?,
        output: output.ok_or(SnapshotError::InvalidArguments)?,
        purpose,
    })
}

/// Rejects wildcard, missing, non-ASCII and unrelated serial identity forms.
fn validate_serial(serial: &str) -> Result<(), SnapshotError> {
    if serial.len() != 12
        || !serial.starts_with("00")
        || !serial.bytes().all(|value| value.is_ascii_digit())
    {
        return Err(SnapshotError::InvalidArguments);
    }
    Ok(())
}

/// Selects one exact serial only; no wildcard, first-device or ambiguity fallback.
fn select_unique_serial<'a>(
    serial: &str,
    candidates: impl IntoIterator<Item = Option<&'a str>>,
) -> Result<usize, SnapshotError> {
    validate_serial(serial)?;
    let mut matches = candidates
        .into_iter()
        .enumerate()
        .filter(|(_, candidate)| *candidate == Some(serial));
    let selected = matches.next().ok_or(SnapshotError::TargetMissing)?.0;
    if matches.next().is_some() {
        return Err(SnapshotError::TargetAmbiguous);
    }
    Ok(selected)
}

/// Rejects existing paths, including dangling symlinks, before opening hardware.
fn ensure_new_output(path: &Path) -> Result<(), SnapshotError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(SnapshotError::InvalidArguments);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(SnapshotError::OutputUnavailable),
    }
}

/// Collects a complete same-lease response sequence before creating any output.
fn capture_to_file(
    usb_serial: &str,
    usb: UsbIdentity,
    path: &Path,
    purpose: SnapshotPurpose,
    read: &mut impl FnMut(SnapshotRead) -> Result<Vec<u8>, SnapshotError>,
) -> Result<(), SnapshotFailure> {
    validate_serial(usb_serial).map_err(|error| error.at(SnapshotStage::Arguments))?;
    ensure_new_output(path).map_err(|error| error.at(SnapshotStage::OutputPreflight))?;
    let inquiry =
        read(SnapshotRead::Inquiry).map_err(|error| error.at(SnapshotStage::InquiryInitial))?;
    validate_inquiry(&inquiry, purpose).map_err(|error| error.at(SnapshotStage::InquiryInitial))?;
    let factory = read(SnapshotRead::FactoryInfo)
        .map_err(|error| error.at(SnapshotStage::ReadFactoryInfo))?;
    if factory.len() != 172 {
        return Err(SnapshotError::IncompleteResponse.at(SnapshotStage::ReadFactoryInfo));
    }
    if factory[16..26] != usb_serial.as_bytes()[2..] {
        return Err(SnapshotError::IdentityChanged.at(SnapshotStage::ReadFactoryInfo));
    }
    let usb_response = read(SnapshotRead::UsbIdentity)
        .map_err(|error| error.at(SnapshotStage::ReadUsbIdentityBuffer))?;
    if usb_response.len() != 32 {
        return Err(SnapshotError::IncompleteResponse.at(SnapshotStage::ReadUsbIdentityBuffer));
    }
    let drive_log =
        read(SnapshotRead::DriveLog).map_err(|error| error.at(SnapshotStage::ReadDriveLog))?;
    let page = parse_log_page(&drive_log)
        .map_err(|_| SnapshotError::IncompleteResponse.at(SnapshotStage::ReadDriveLog))?;
    if page.page_code() != 0x20 {
        return Err(SnapshotError::IncompleteResponse.at(SnapshotStage::ReadDriveLog));
    }
    let load_count = page
        .find(1)
        .and_then(|value| value.uint32())
        .ok_or(SnapshotError::IncompleteResponse.at(SnapshotStage::ReadDriveLog))?;
    let mode_response =
        read(SnapshotRead::ModeSense).map_err(|error| error.at(SnapshotStage::ReadModeSense))?;
    let mode = RdxFeaturePage::parse(&mode_response)
        .map_err(|_| SnapshotError::IncompleteResponse.at(SnapshotStage::ReadModeSense))?;
    let operation_mode = mode
        .operation_mode()
        .filter(|value| (1..=3).contains(value))
        .ok_or(SnapshotError::IncompleteResponse.at(SnapshotStage::ReadModeSense))?;
    // A final unchanged reply checks the identity after every factory/status read.
    if read(SnapshotRead::Inquiry).map_err(|error| error.at(SnapshotStage::InquiryFinal))?
        != inquiry
    {
        return Err(SnapshotError::IdentityChanged.at(SnapshotStage::InquiryFinal));
    }
    let snapshot = Snapshot {
        schema_version: 1,
        kind: purpose.kind(),
        device: SnapshotDevice {
            usb_serial,
            inquiry_revision: purpose.revision(),
            usb_location_id: usb.location_id,
            usb_vendor_id: usb.vendor_id,
            usb_product_id: usb.product_id,
        },
        inquiry_hex: hex(&inquiry),
        factory_info_hex: hex(&factory),
        usb_identity_hex: hex(&usb_response),
        load_count,
        operation_mode,
        raw_responses: RawResponses {
            drive_log_hex: hex(&drive_log),
            mode_sense_hex: hex(&mode_response),
        },
    };
    let bytes = serde_json::to_vec(&snapshot)
        .map_err(|_| SnapshotError::OutputUnavailable.at(SnapshotStage::WriteOutput))?;
    write_private_output(path, &bytes).map_err(|error| error.at(SnapshotStage::WriteOutput))
}

/// Requires complete standard disk identity and the purpose's fixed revision.
fn validate_inquiry(bytes: &[u8], purpose: SnapshotPurpose) -> Result<(), SnapshotError> {
    if !(36..=254).contains(&bytes.len())
        || bytes[4] < 31
        || usize::from(bytes[4]) + 5 > bytes.len()
    {
        return Err(SnapshotError::IncompleteResponse);
    }
    if bytes[0] & 0x1f != 0
        || &bytes[8..16] != b"TANDBERG"
        || &bytes[16..32] != b"RDX             "
        || &bytes[32..36] != purpose.revision().as_bytes()
    {
        return Err(match purpose {
            SnapshotPurpose::MigrationSource => SnapshotError::UnsupportedFirmware,
            SnapshotPurpose::RestorationReadback => SnapshotError::ReadbackRevisionMismatch,
        });
    }
    Ok(())
}

/// Encodes bounded private bytes solely for the explicit snapshot file.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

/// Creates one new owner-only file after validation, never following an old link.
fn write_private_output(path: &Path, bytes: &[u8]) -> Result<(), SnapshotError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| SnapshotError::OutputUnavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| SnapshotError::OutputUnavailable)
}

#[cfg(test)]
mod tests;
