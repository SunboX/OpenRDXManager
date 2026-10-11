// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS adapter for the isolated, closed read-only collector.

use rdx_macos_native::{Completion, MacDevice, NativeError, ScsiOperation};

use super::*;

/// Retains one native device and exclusive lease until the one-shot process exits.
pub(super) fn run(arguments: Arguments) -> ! {
    let (mut device, selected_usb) = match select_device(&arguments.usb_serial) {
        Ok(selected) => selected,
        Err(error) => finish_and_exit(Err(error)),
    };
    {
        let mapping = match device.pin_media() {
            Ok(mapping) => mapping,
            Err(error) => finish_and_exit(Err(native_error(error).at(SnapshotStage::PinMedia))),
        };
        if mapping.mounted_media_count() != 0 {
            finish_and_exit(Err(SnapshotError::DeviceBusy.at(SnapshotStage::PinMedia)));
        }
    }
    let usb = match device.usb_identity() {
        Ok(identity)
            if identity.serial() == selected_usb.serial()
                && identity.location_id() == selected_usb.location_id()
                && identity.vendor_id() == selected_usb.vendor_id()
                && identity.product_id() == selected_usb.product_id() =>
        {
            UsbIdentity {
                location_id: identity.location_id(),
                vendor_id: identity.vendor_id(),
                product_id: identity.product_id(),
            }
        }
        Err(error) => finish_and_exit(Err(
            native_error(error).at(SnapshotStage::RevalidateUsbIdentity)
        )),
        Ok(_) => finish_and_exit(Err(
            SnapshotError::IdentityChanged.at(SnapshotStage::RevalidateUsbIdentity)
        )),
    };
    rdx_macos_native::enable_acquisition_diagnostics();
    let mut lease = match device.acquire_scsi() {
        Ok(lease) => lease,
        Err(error) => finish_and_exit(Err(native_error(error).at(SnapshotStage::AcquireScsi))),
    };
    let result = capture_to_file(
        &arguments.usb_serial,
        usb,
        &arguments.output,
        arguments.purpose,
        &mut |read| {
            let (operation, maximum) = match read {
                SnapshotRead::Inquiry => (ScsiOperation::inquiry_standard(), 254),
                SnapshotRead::FactoryInfo => (ScsiOperation::vendor_0283_factory_info(), 172),
                SnapshotRead::UsbIdentity => (ScsiOperation::vendor_0283_usb_identity(), 32),
                SnapshotRead::DriveLog => (ScsiOperation::log_sense_drive(), 254),
                SnapshotRead::ModeSense => (ScsiOperation::mode_sense_sata(), 254),
            };
            read_completion(lease.execute(operation), maximum)
        },
    );
    // USB capture surrender can terminate its owner. Persisted output and fixed
    // status precede process exit; the OS then reclaims both retained leases.
    finish_and_exit(result)
}

/// Resolves actual USB serials without acquiring transport on unselected devices.
fn select_device(
    usb_serial: &str,
) -> Result<(MacDevice, rdx_macos_native::MacUsbIdentity), SnapshotFailure> {
    let candidates = match rdx_macos_native::enumerate_candidates() {
        Ok(candidates) => candidates,
        Err(error) => return Err(native_error(error).at(SnapshotStage::EnumerateCandidates)),
    };
    let mut identified = Vec::new();
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.matches_rdx_identity_hint())
    {
        let mut device = MacDevice::open(candidate)
            .map_err(|error| native_error(error).at(SnapshotStage::OpenCandidate))?;
        // SCSI unit serial and USB ancestor serial are separate identity domains.
        // Never synthesize a USB serial by prefixing a SCSI serial.
        let identity = device
            .usb_identity()
            .map_err(|error| native_error(error).at(SnapshotStage::ReadUsbIdentity))?;
        identified.push((device, identity));
    }
    let index = select_unique_serial(
        usb_serial,
        identified.iter().map(|(_, usb)| Some(usb.serial())),
    )
    .map_err(|error| error.at(SnapshotStage::SelectDevice))?;
    Ok(identified.swap_remove(index))
}

/// Accepts only GOOD, complete, bounded data-in replies, never printing sense/data.
fn read_completion(completion: Completion, maximum: usize) -> Result<Vec<u8>, SnapshotError> {
    match completion {
        Completion::Device {
            scsi_status: 0,
            service_response: 2,
            transferred_length,
            data,
            sense_reported_length: 0,
            sense,
        } if sense.is_empty()
            && data.len() == transferred_length as usize
            && !data.is_empty()
            && data.len() <= maximum =>
        {
            Ok(data)
        }
        Completion::NotAttempted(error) | Completion::AttemptedError(error) => {
            Err(native_error(error))
        }
        _ => Err(SnapshotError::IncompleteResponse),
    }
}

/// Preserves actionable typed prerequisites without retaining native diagnostics.
fn native_error(error: NativeError) -> SnapshotError {
    SnapshotError::Native(match error {
        NativeError::UnsupportedPlatform => NativeFailureKind::UnsupportedPlatform,
        NativeError::InvalidRequest => NativeFailureKind::InvalidRequest,
        NativeError::TransportUnavailable => NativeFailureKind::TransportUnavailable,
        NativeError::AccessDenied => NativeFailureKind::AccessDenied,
        NativeError::Busy => NativeFailureKind::Busy,
        NativeError::TimedOut => NativeFailureKind::TimedOut,
        NativeError::DeviceRemoved => NativeFailureKind::DeviceRemoved,
        NativeError::EnumerationFailed => NativeFailureKind::EnumerationFailed,
        NativeError::ResourceLimit => NativeFailureKind::ResourceLimit,
        NativeError::EvidenceIncomplete => NativeFailureKind::EvidenceIncomplete,
        NativeError::Other => NativeFailureKind::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contradictory transfer lengths, status or sense cannot become file evidence.
    #[test]
    fn incomplete_native_completions_are_rejected() {
        for completion in [
            Completion::Device {
                scsi_status: 0,
                service_response: 2,
                transferred_length: 172,
                data: vec![0; 171],
                sense_reported_length: 0,
                sense: vec![],
            },
            Completion::Device {
                scsi_status: 0,
                service_response: 2,
                transferred_length: 173,
                data: vec![0; 173],
                sense_reported_length: 0,
                sense: vec![],
            },
            Completion::Device {
                scsi_status: 2,
                service_response: 2,
                transferred_length: 172,
                data: vec![0; 172],
                sense_reported_length: 0,
                sense: vec![],
            },
            Completion::Device {
                scsi_status: 0,
                service_response: 2,
                transferred_length: 172,
                data: vec![0; 172],
                sense_reported_length: 1,
                sense: vec![0],
            },
        ] {
            assert_eq!(
                read_completion(completion, 172),
                Err(SnapshotError::IncompleteResponse)
            );
        }
        assert_eq!(
            read_completion(Completion::NotAttempted(NativeError::AccessDenied), 172),
            Err(SnapshotError::Native(NativeFailureKind::AccessDenied))
        );
    }

    /// Every native status survives as its fixed code across pin/acquire/read stages.
    #[test]
    fn native_diagnostics_preserve_all_closed_failure_kinds() {
        for (error, expected) in [
            (NativeError::UnsupportedPlatform, "unsupported-platform"),
            (NativeError::InvalidRequest, "invalid-request"),
            (NativeError::TransportUnavailable, "transport-unavailable"),
            (NativeError::AccessDenied, "access-denied"),
            (NativeError::Busy, "busy"),
            (NativeError::TimedOut, "timed-out"),
            (NativeError::DeviceRemoved, "device-removed"),
            (NativeError::EnumerationFailed, "enumeration-failed"),
            (NativeError::ResourceLimit, "resource-limit"),
            (NativeError::EvidenceIncomplete, "evidence-incomplete"),
            (NativeError::Other, "other"),
        ] {
            for (stage, expected_stage) in [
                (SnapshotStage::PinMedia, "pin-media"),
                (SnapshotStage::AcquireScsi, "acquire-scsi"),
                (SnapshotStage::InquiryInitial, "inquiry-initial"),
            ] {
                let mut output = Vec::new();
                native_error(error).at(stage).write_to(&mut output).unwrap();
                assert!(output.len() < 384);
                let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
                assert_eq!(value["stage"], expected_stage);
                assert_eq!(value["nativeError"], expected);
                assert_eq!(value.as_object().unwrap().len(), 4);
            }
        }
    }
}
