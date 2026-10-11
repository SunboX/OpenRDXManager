#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed user-facing serial commands; offline preparation never opens a receiver.
//!
//! Other hosts compile the complete parser and offline plan for tests, but the
//! hardware-facing branches return the fixed unsupported-platform result.

use serde_json::{Value, json};
use std::ffi::OsString;
use std::path::PathBuf;
mod flow;
#[cfg(target_os = "macos")]
mod native;
mod plan;
use rdx_service::serial_record as record;
#[cfg(unix)]
mod storage;
#[cfg(test)]
mod tests;

pub(super) type Error = &'static str;
pub(super) type Result<T> = std::result::Result<T, Error>;

/// Exact user-supplied device selection, with no wildcard or integer serial conversion.
#[derive(Clone)]
pub(super) struct Target {
    pub serial: String,
    pub location: u32,
}

/// The only public actions accepted by the utility.
enum Action {
    Inspect {
        target: Target,
    },
    Prepare {
        target: Target,
        new_serial: String,
        output: PathBuf,
        sector_file: Option<PathBuf>,
        reconstruct: bool,
    },
    Apply {
        plan_dir: PathBuf,
    },
    Help,
}

/// Parses every argument before reading files, acquiring ownership, or enumerating hardware.
fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Action> {
    let mut args = arguments.collect::<Vec<_>>().into_iter();
    let command = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("serial-command-required")?;
    if command == "--help" && args.len() == 0 {
        return Ok(Action::Help);
    }
    if !matches!(command.as_str(), "inspect" | "prepare" | "apply") {
        return Err("serial-invalid-arguments");
    }
    let mut serial = None;
    let mut location = None;
    let mut new_serial = None;
    let mut output = None;
    let mut sector_file = None;
    let mut plan_dir = None;
    let mut reconstruct = false;
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("--reconstruct-erased") if command == "prepare" && !reconstruct => {
                reconstruct = true
            }
            Some("--usb-serial") if command != "apply" && serial.is_none() => {
                let value = args
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("serial-invalid-arguments")?;
                record::validate_usb_serial(&value)?;
                serial = Some(value);
            }
            Some("--location-id") if command != "apply" && location.is_none() => {
                let value = args
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("serial-invalid-arguments")?;
                let parsed = if let Some(hex) = value.strip_prefix("0x") {
                    u32::from_str_radix(hex, 16)
                } else {
                    value.parse()
                };
                location = Some(
                    parsed
                        .ok()
                        .filter(|value| *value != 0)
                        .ok_or("serial-location-required")?,
                );
            }
            Some("--new-unit-serial") if command == "prepare" && new_serial.is_none() => {
                let value = args
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("serial-invalid-arguments")?;
                if value.len() != 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("serial-invalid-unit-serial");
                }
                new_serial = Some(format!("00{value}"));
            }
            Some("--new-usb-serial") if command == "prepare" && new_serial.is_none() => {
                let value = args
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("serial-invalid-arguments")?;
                record::validate_usb_serial(&value)?;
                new_serial = Some(value);
            }
            Some("--output-dir") if command == "prepare" && output.is_none() => {
                output = Some(path_argument(&mut args)?)
            }
            Some("--sector-file") if command == "prepare" && sector_file.is_none() => {
                sector_file = Some(path_argument(&mut args)?)
            }
            Some("--plan-dir") if command == "apply" && plan_dir.is_none() => {
                plan_dir = Some(path_argument(&mut args)?)
            }
            _ => return Err("serial-invalid-arguments"),
        }
    }
    if command == "apply" {
        return Ok(Action::Apply {
            plan_dir: plan_dir.ok_or("serial-plan-required")?,
        });
    }
    let target = Target {
        serial: serial.ok_or("serial-exact-target-required")?,
        location: location.ok_or("serial-location-required")?,
    };
    if command == "inspect" {
        return Ok(Action::Inspect { target });
    }
    Ok(Action::Prepare {
        target,
        new_serial: new_serial.ok_or("serial-new-serial-required")?,
        output: output.ok_or("serial-output-required")?,
        sector_file,
        reconstruct,
    })
}

/// Requires a clean absolute path; descriptor-relative storage rejects symlink components.
fn path_argument(args: &mut impl Iterator<Item = OsString>) -> Result<PathBuf> {
    let path = PathBuf::from(args.next().ok_or("serial-invalid-arguments")?);
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("serial-path-must-be-absolute");
    }
    Ok(path)
}

/// Emits structured record diagnostics while keeping all unrelated manufacturing bytes private.
fn inspection(sector: &record::Sector, target: &Target, revision: Option<&str>) -> Value {
    let record_serial = record::record_usb_serial(sector);
    json!({"status": "ok", "command": "inspect", "usbSerial": target.serial,
        "usbLocationId": target.location, "inquiryRevision": revision,
        "recordState": record::state(sector), "recordUsbSerial": record_serial,
        "usbMatchesRecord": record_serial.as_deref().map(|serial| serial == target.serial),
        "sectorSha256": record::sha256(sector), "sectorCrc32": record::crc32(sector)})
}

/// Runs one closed command and returns JSON only after cleanup completes.
pub(super) fn run(arguments: impl Iterator<Item = OsString>) -> Result<Value> {
    match parse(arguments)? {
        Action::Help => Ok(json!({"status": "ok", "commands": [
            "inspect --usb-serial <00+10 digits> --location-id <nonzero decimal or 0xhex>",
            "prepare --usb-serial <current> --location-id <location> (--new-usb-serial <12 digits> | --new-unit-serial <10 digits>) --output-dir <new absolute directory> [--sector-file <absolute 4096-byte file>] [--reconstruct-erased]",
            "apply --plan-dir <absolute prepared directory>"
        ]})),
        Action::Inspect { target } => inspect_device(&target),
        Action::Prepare {
            target,
            new_serial,
            output,
            sector_file,
            reconstruct,
        } => {
            #[cfg(unix)]
            {
                let (sector, source) = if let Some(path) = sector_file {
                    (
                        storage::read_offline_sector(&path)?,
                        "offline-unverified-device",
                    )
                } else {
                    (read_device(&target)?, "device-readback")
                };
                let plan = plan::Plan::new(
                    &sector,
                    target.serial,
                    target.location,
                    new_serial,
                    reconstruct,
                )?;
                storage::Evidence::create(&output, &plan, &sector)?;
                Ok(
                    json!({"status": "ok", "command": "prepare", "source": source,
                    "newUsbSerial": plan.new_usb_serial, "originalFactoryDataLost": plan.original_factory_data_lost,
                    "recordState": plan.original_record_state, "sectorSha256": plan.sector_sha256,
                    "hardwareMutationPerformed": false}),
                )
            }
            #[cfg(not(unix))]
            {
                let _ = (target, new_serial, output, sector_file, reconstruct);
                Err("serial-platform-unsupported")
            }
        }
        Action::Apply { plan_dir } => {
            #[cfg(target_os = "macos")]
            {
                native::apply(&plan_dir)
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = plan_dir;
                Err("serial-platform-unsupported")
            }
        }
    }
}

/// Dispatches device inspection only on the supported native host.
fn inspect_device(target: &Target) -> Result<Value> {
    #[cfg(target_os = "macos")]
    {
        native::inspect(target)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = target;
        Err("serial-platform-unsupported")
    }
}

/// Dispatches read-only sector capture only on the supported native host.
fn read_device(target: &Target) -> Result<record::Sector> {
    #[cfg(target_os = "macos")]
    {
        native::read_sector(target)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = target;
        Err("serial-platform-unsupported")
    }
}
