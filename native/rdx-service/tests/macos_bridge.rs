// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::model::RiskClass;
use rdx_service::platform::PlatformBackend;
use rdx_service::platform::macos::{
    MacOsBackend, MacOsIoFailure, MacOsReadinessFacts, MacOsReadinessIssue,
    NativeScsiTaskCompletion, build_scsi_task, convert_scsi_task_completion,
    evaluate_macos_readiness,
};
use rdx_service::protocol::{InquiryPage, inquiry, self_test};
use rdx_service::service::{NoDeviceBackend, ServiceBackend, ServiceMode, ServicePlatform};
use rdx_service::transport::{CommandDispatch, TransportError};

/// Missing safe SCSI task support leaves discovery truthful without claiming
/// transport, privilege, host mutations, or physical hardware verification.
#[test]
fn safe_interface_absence_is_a_transport_capability_result() {
    let report =
        evaluate_macos_readiness(MacOsReadinessFacts::new(true, false, true, false, false));

    assert_eq!(
        report.issue(),
        MacOsReadinessIssue::PlatformPassThroughUnavailable
    );
    let capabilities = report.capabilities();
    assert!(capabilities.discovery_available());
    assert!(!capabilities.transport_available());
    assert!(!capabilities.privileged());
    assert!(!capabilities.safe_eject_available());
    assert!(!capabilities.force_eject_available());
    assert!(!capabilities.format_available());
    assert!(!capabilities.drive_letter_available());
    assert!(!capabilities.hardware_verified());
}

/// Service metadata is diagnostic evidence only and cannot manufacture
/// current-process authority or enable transport on its own.
#[test]
fn service_metadata_never_stands_in_for_runtime_authority() {
    let report = evaluate_macos_readiness(MacOsReadinessFacts::new(true, true, true, true, false));

    assert_eq!(
        report.issue(),
        MacOsReadinessIssue::PrivilegedServiceUnavailable
    );
    assert!(report.capabilities().discovery_available());
    assert!(report.capabilities().transport_available());
    assert!(!report.capabilities().privileged());
}

/// A current authorized helper publishes implemented host operations while
/// keeping physical-hardware verification independent and false.
#[test]
fn current_service_authority_advertises_implemented_host_mutations() {
    let report = evaluate_macos_readiness(MacOsReadinessFacts::new(true, true, true, true, true));

    assert_eq!(report.issue(), MacOsReadinessIssue::ReadyHardwareUnverified);
    let capabilities = report.capabilities();
    assert!(capabilities.discovery_available());
    assert!(capabilities.transport_available());
    assert!(capabilities.privileged());
    assert!(capabilities.safe_eject_available());
    assert!(capabilities.format_available());
    assert!(capabilities.write_read_available());
    assert!(!capabilities.force_eject_available());
    assert!(!capabilities.hardware_verified());
}

/// The portable packet retains semantic identity and bounded task fields but
/// exposes no caller-authored raw CDB submission API.
#[test]
fn trusted_inquiry_maps_to_one_bounded_scsi_task() {
    let packet = build_scsi_task(&inquiry(InquiryPage::DeviceIdentification))
        .expect("trusted VPD inquiry is supported");

    assert_eq!(packet.risk(), RiskClass::ReadOnly);
    assert_eq!(packet.transfer_length(), 0xFE);
    assert_eq!(packet.timeout_ms(), 30_000);
    assert_eq!(format!("{packet:?}"), "MacOsScsiTask(<private>)");
}

/// Factory capture commands retain bounded receive lengths and read-only risk.
#[test]
fn trusted_factory_reads_map_to_read_only_tasks() {
    for (command, length) in [
        (rdx_service::protocol::vendor_0283_factory_info(), 172),
        (rdx_service::protocol::vendor_0283_usb_identity(), 32),
    ] {
        let packet = build_scsi_task(&command).expect("fixed factory read is supported");
        assert_eq!(packet.risk(), RiskClass::ReadOnly);
        assert_eq!(packet.transfer_length(), length);
    }
}

/// A native failure before `ExecuteTaskSync` proves the device did not see the
/// command and therefore preserves the NotSent terminal.
#[test]
fn pre_execute_failure_is_definitely_not_sent() {
    let packet = build_scsi_task(&self_test()).expect("trusted self-test");

    assert_eq!(
        convert_scsi_task_completion(
            &packet,
            NativeScsiTaskCompletion::not_attempted(MacOsIoFailure::Busy),
        ),
        CommandDispatch::NotSent(TransportError::Unavailable)
    );
}

/// Once the synchronous task API is invoked, even a returned timeout cannot
/// prove whether a mutating command completed on the device.
#[test]
fn invoked_mutation_timeout_has_unknown_completion() {
    let packet = build_scsi_task(&self_test()).expect("trusted self-test");

    assert_eq!(
        convert_scsi_task_completion(
            &packet,
            NativeScsiTaskCompletion::attempted_error(MacOsIoFailure::TimedOut),
        ),
        CommandDispatch::CompletionUnknown(TransportError::Timeout)
    );
}

/// Production activation is target-gated; every host still receives a
/// cross-field-consistent matrix and physical verification remains false.
#[test]
fn native_backend_never_claims_physical_hardware_proof() {
    let backend = MacOsBackend::native();
    let capabilities = backend.capabilities();

    assert!(!capabilities.hardware_verified());
    #[cfg(not(target_os = "macos"))]
    {
        assert!(!capabilities.discovery_available());
        assert!(!capabilities.transport_available());
    }
}

/// A known non-SCSI IOKit service must not be accepted merely because it has a
/// valid registry entry identifier.
#[cfg(target_os = "macos")]
#[test]
fn wrong_iokit_service_reports_platform_pass_through_unavailable() {
    assert_eq!(
        rdx_macos_native::probe_known_non_scsi_service_for_test(),
        Err(rdx_macos_native::NativeError::TransportUnavailable)
    );
}

/// The executable may publish native discovery readiness while its deliberately
/// empty Task 4 backend still rejects every hardware operation.
#[test]
fn empty_service_backend_carries_truthful_macos_readiness() {
    let report =
        evaluate_macos_readiness(MacOsReadinessFacts::new(true, false, true, false, false));
    let backend =
        NoDeviceBackend::from_platform_capabilities(ServicePlatform::Darwin, report.capabilities());
    let descriptor = backend.descriptor();

    assert_eq!(descriptor.mode(), ServiceMode::Native);
    assert!(!descriptor.privileged());
    assert_eq!(
        descriptor.platform_capability_state(),
        "transport-unavailable"
    );
    assert_eq!(
        descriptor.platform_capability_reason(),
        Some("raw-transport-unavailable")
    );
}
