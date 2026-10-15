// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact USB selection and disposable macOS capture ownership for the serial CLI.

use rdx_macos_native::{
    Completion, MacDevice, MacRematchIdentity, MacScsiWorkerLease, MacUsbIdentity, NativeError,
    ScsiOperation,
};
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, Instant};

use super::{
    Result, Target,
    flow::{self, SerialTransport},
    record::{self, Sector},
    storage::Evidence,
};

/// Maps native failures to fixed actionable codes without leaking device payloads or paths.
fn native_error(error: NativeError) -> &'static str {
    match error {
        NativeError::AccessDenied => "serial-access-denied-run-in-authorized-terminal",
        NativeError::Busy => "serial-device-or-service-busy",
        NativeError::DeviceRemoved => "serial-target-identity-changed",
        NativeError::TimedOut => "serial-native-timeout",
        NativeError::EvidenceIncomplete => "serial-native-evidence-incomplete",
        _ => "serial-native-transport-unavailable",
    }
}

/// Keeps the exact root-owned global execution guard alive until all capture cleanup completes.
fn ownership() -> Result<rdx_macos_native::HardwareOwnershipGuard> {
    rdx_macos_native::initialize_hardware_ownership_namespace().map_err(native_error)?;
    rdx_macos_native::try_acquire_hardware_ownership().map_err(native_error)
}

/// Requires complete actual USB ancestor properties matching the explicit target tuple.
fn matches_usb(usb: &MacUsbIdentity, target: &Target) -> bool {
    usb.vendor_id() == 0x1a5a
        && usb.product_id() == 5
        && usb.location_id() != 0
        && usb.location_id() == target.location
        && usb.serial() == target.serial
}

/// Opens only nonexclusive candidate authority and refuses zero or multiple exact matches.
fn select(target: &Target) -> Result<(MacDevice, MacRematchIdentity)> {
    let candidates = rdx_macos_native::enumerate_candidates().map_err(native_error)?;
    let mut selected = None;
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.matches_rdx_identity_hint())
    {
        let mut device = MacDevice::open(candidate).map_err(native_error)?;
        let usb = device.usb_identity().map_err(native_error)?;
        if matches_usb(&usb, target) {
            if selected.is_some() {
                return Err("serial-target-ambiguous");
            }
            selected = Some((device, candidate.rematch_identity()));
        }
    }
    selected.ok_or("serial-exact-target-not-found")
}

/// Selects, pins, revalidates, acquires, and checks the capture owner's actual USB identity.
fn acquire(target: &Target) -> Result<NativeTransport> {
    let (mut device, identity) = select(target)?;
    {
        let mapping = device.pin_media().map_err(native_error)?;
        if mapping.mounted_media_count() != 0 {
            return Err("serial-mounted-media-refused");
        }
    }
    if !matches_usb(&device.usb_identity().map_err(native_error)?, target) {
        return Err("serial-target-identity-changed");
    }
    drop(device);
    let mut worker = rdx_macos_native::MacDirectWorkerFactory::for_current_privileged_process()
        .and_then(|factory| factory.spawn(&identity))
        .map_err(native_error)?;
    if !matches_usb(&worker.usb_identity().map_err(native_error)?, target) {
        worker.release_for_storage_rematch().map_err(native_error)?;
        return Err("serial-target-identity-changed");
    }
    Ok(NativeTransport { worker })
}

/// Owns one disposable capture worker, so terminating USB cleanup cannot terminate this CLI.
struct NativeTransport {
    worker: MacScsiWorkerLease,
}

/// Accepts only exact GOOD responses, including realized outbound/no-data transfer lengths.
fn completion(completion: Completion, length: Option<usize>, outbound: bool) -> Result<Vec<u8>> {
    match completion {
        Completion::Device {
            scsi_status: 0,
            service_response: 2,
            transferred_length,
            data,
            sense_reported_length: 0,
            sense,
        } if sense.is_empty()
            && if outbound {
                data.is_empty() && Some(transferred_length as usize) == length
            } else {
                data.len() == transferred_length as usize
                    && length.map_or(!data.is_empty() && data.len() <= 254, |length| {
                        data.len() == length
                    })
            } =>
        {
            Ok(data)
        }
        Completion::NotAttempted(error) | Completion::AttemptedError(error) => {
            Err(native_error(error))
        }
        _ => Err("serial-scsi-completion-not-good"),
    }
}

impl SerialTransport for NativeTransport {
    /// Executes only standard INQUIRY.
    fn inquiry(&mut self) -> Result<Vec<u8>> {
        completion(
            self.worker.execute(ScsiOperation::inquiry_standard()),
            None,
            false,
        )
    }
    /// Executes only drive LOG SENSE page 20h.
    fn drive_log(&mut self) -> Result<Vec<u8>> {
        completion(
            self.worker.execute(ScsiOperation::log_sense_drive()),
            None,
            false,
        )
    }
    /// Reads only the fixed RDXM physical-sensor diagnostic frame.
    fn mechanism_diagnostics(&mut self) -> Result<Vec<u8>> {
        completion(
            self.worker
                .execute(ScsiOperation::openrdx_mechanism_diagnostics()),
            Some(128),
            false,
        )
    }
    /// Executes only the separately validated sector chunk index.
    fn sector_chunk(&mut self, index: u8) -> Result<Vec<u8>> {
        completion(
            self.worker.execute(
                ScsiOperation::openrdx_manufacturing_sector_chunk(index).map_err(native_error)?,
            ),
            Some(128),
            false,
        )
    }
    /// Executes the fixed non-mutating capability probe.
    fn capability(&mut self) -> Result<()> {
        completion(
            self.worker
                .execute(ScsiOperation::openrdx_serial_capability()),
            Some(0),
            true,
        )
        .map(|_| ())
    }
    /// Executes one fixed compare-and-set serial payload.
    fn set_serial(&mut self, payload: Vec<u8>) -> Result<()> {
        let operation = ScsiOperation::openrdx_set_serial(payload).map_err(native_error)?;
        completion(self.worker.execute(operation), Some(280), true).map(|_| ())
    }
}

/// Always releases the capture owner before propagating the operation result.
fn release<T>(transport: NativeTransport, result: Result<T>) -> Result<T> {
    let cleanup = transport
        .worker
        .release_for_storage_rematch()
        .map_err(native_error);
    match result {
        Ok(value) => {
            cleanup?;
            Ok(value)
        }
        Err(error) => {
            cleanup?;
            Err(error)
        }
    }
}

/// Captures fresh read-only evidence and returns the byte-free structured inspection.
pub(super) fn inspect(target: &Target) -> Result<Value> {
    let _ownership = ownership()?;
    let mut transport = acquire(target)?;
    let result = flow::snapshot(&mut transport)
        .map(|(sector, revision)| super::inspection(&sector, target, Some(&revision)));
    release(transport, result)
}

/// Reads the full sector with fresh empty-bay checks and closes every capture handle.
pub(super) fn read_sector(target: &Target) -> Result<Sector> {
    let _ownership = ownership()?;
    let mut transport = acquire(target)?;
    let result = flow::snapshot(&mut transport).map(|(sector, _)| sector);
    release(transport, result)
}

/// Applies only a durable prepared plan, then verifies full flash and same-port USB identity.
pub(super) fn apply(path: &Path) -> Result<Value> {
    let evidence = Evidence::open(path)?;
    let (plan, backup) = evidence.load()?;
    let target = Target {
        serial: plan.expected_usb_serial.clone(),
        location: plan.usb_location_id,
    };
    let _ownership = ownership()?;
    let mut transport = acquire(&target)?;
    let result = flow::apply_record(&mut transport, &plan, &backup, &target, || {
        // Re-read the pinned private evidence immediately before the irreversible step.
        let (disk_plan, disk_sector) = evidence.load()?;
        if serde_json::to_value(&disk_plan).ok() != serde_json::to_value(&plan).ok()
            || disk_sector != backup
        {
            return Err("serial-plan-evidence-changed");
        }
        evidence.write_new(
            "apply-attempt.json",
            &serde_json::to_vec(
                &json!({"status": "write-may-follow", "newUsbSerial": plan.new_usb_serial,
            "expectedSectorSha256": plan.expected_sector_sha256}),
            )
            .map_err(|_| "serial-plan-invalid")?,
        )
    });
    let readback = match result {
        Ok(readback) => readback,
        Err(error) => return release(transport, Err(error)),
    };
    let pre_reset = evidence.write_new("readback-before-reset.bin", &readback);
    if let Err(error) = pre_reset {
        return release(transport, Err(error));
    }
    // Only an independently byte-identical full-sector readback permits the existing unit reset.
    let reset = completion(
        transport.worker.execute(ScsiOperation::unit_reset()),
        Some(0),
        true,
    );
    let reset_good = reset.is_ok();
    release(transport, Ok(()))?;
    // A reset may disconnect before GOOD reaches the host; only actual re-enumeration proves success.
    let new_target = Target {
        serial: plan.new_usb_serial.clone(),
        location: target.location,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match select(&new_target) {
            Ok((mut device, _)) => {
                let usb = device.usb_identity().map_err(native_error)?;
                if matches_usb(&usb, &new_target) {
                    break;
                }
            }
            Err("serial-target-ambiguous") => return Err("serial-target-ambiguous-after-reset"),
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err("serial-written-usb-reenumeration-unverified");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let receipt = json!({"status": "ok", "command": "apply", "newUsbSerial": new_target.serial,
        "usbLocationId": new_target.location, "sectorSha256": record::sha256(&readback),
        "originalFactoryDataLost": plan.original_factory_data_lost, "resetGoodReceived": reset_good,
        "fullSectorReadbackVerified": true, "usbReenumerationVerified": true});
    evidence.write_new(
        "applied.json",
        &serde_json::to_vec_pretty(&receipt).map_err(|_| "serial-plan-invalid")?,
    )?;
    Ok(receipt)
}
