// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(not(windows))]
use rdx_service::platform::PlatformBackend;
#[cfg(not(windows))]
use rdx_service::platform::windows::WindowsBackend;
use rdx_service::platform::windows::{
    NativeScsiCompletion, PassThroughKind, SCSI_IOCTL_DATA_IN, SCSI_IOCTL_DATA_UNSPECIFIED,
    WINDOWS_SENSE_CAPACITY, WindowsIoFailure, WindowsResultError, build_scsi_pass_through,
    convert_scsi_completion, normalize_windows_candidate, parse_scsi_result,
};
use rdx_service::protocol::{
    InquiryPage, inquiry, led_test, log_sense, mode_select, mode_sense, security_in, self_test,
    unit_reset, write_buffer,
};
use rdx_service::transport::{CommandDispatch, TransportError};

/// Data-bearing commands use direct SPTI with the exact trusted command fields.
#[test]
fn direct_pass_through_has_exact_cdb_direction_timeout_and_lengths() {
    let command = log_sense(0x20).expect("proven RDX log page");
    let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");

    assert_eq!(packet.kind(), PassThroughKind::Direct);
    assert_eq!(packet.cdb(), &[0x4D, 0, 0x20, 0, 0, 0, 0, 0, 0xFE, 0]);
    assert_eq!(packet.data_direction(), SCSI_IOCTL_DATA_IN);
    assert_eq!(packet.transfer_length(), 0xFE);
    assert_eq!(packet.timeout_seconds(), 30);
}

/// The production constructor never enables Windows native claims on another OS.
#[cfg(not(windows))]
#[test]
fn native_windows_backend_is_target_gated_on_non_windows_hosts() {
    let backend = WindowsBackend::native();

    assert!(!backend.capabilities().discovery_available());
    assert!(!backend.capabilities().transport_available());
    assert!(!backend.capabilities().privileged());
    assert!(!backend.capabilities().hardware_verified());
}

/// SetupAPI instance identity is retained privately while diagnostics stay path-free.
#[test]
fn windows_candidate_normalization_redacts_the_instance_recipe() {
    let instance_id = r"USBSTOR\DISK&VEN_TANDBERG&PROD_RDX\7820999743";
    let candidate =
        normalize_windows_candidate(7, instance_id).expect("bounded SetupAPI candidate");

    assert_eq!(candidate.token(), "windows-disk-7");
    let debug = format!("{candidate:?}");
    assert!(!debug.contains(instance_id));
    assert!(!debug.contains("PhysicalDrive"));
    assert!(debug.contains("<private>"));
}

/// A Win32 dispatch failure cannot be confused with a device SCSI status.
#[test]
fn win32_failure_remains_separate_from_scsi_status() {
    let packet = build_scsi_pass_through(&self_test()).expect("bounded SPTI request");
    let completion = NativeScsiCompletion::attempted_error(WindowsIoFailure::AccessDenied);

    assert_eq!(
        parse_scsi_result(&packet, completion),
        Err(WindowsResultError::Win32 {
            attempted: true,
            failure: WindowsIoFailure::AccessDenied,
        })
    );
}

/// A native timeout is ambiguous once synchronous dispatch may have begun.
#[test]
fn timeout_maps_to_completion_unknown_instead_of_not_sent() {
    let packet = build_scsi_pass_through(&self_test()).expect("bounded SPTI request");
    let completion = NativeScsiCompletion::attempted_error(WindowsIoFailure::TimedOut);

    assert_eq!(
        convert_scsi_completion(&packet, completion),
        CommandDispatch::CompletionUnknown(TransportError::Timeout)
    );
}

/// API-invoked failures are ambiguous for every semantic risk and sanitized error class.
#[test]
fn attempted_win32_failures_are_never_retryable_as_not_sent() {
    let commands = [
        inquiry(InquiryPage::Standard),
        self_test(),
        unit_reset(),
        write_buffer(0x05, 0x012345, &[]).expect("bounded firmware finalize"),
    ];
    let failures = [
        (WindowsIoFailure::AccessDenied, TransportError::Unavailable),
        (WindowsIoFailure::Busy, TransportError::Unavailable),
        (WindowsIoFailure::Cancelled, TransportError::Unavailable),
        (WindowsIoFailure::TimedOut, TransportError::Timeout),
        (
            WindowsIoFailure::DeviceRemoved,
            TransportError::DeviceRemoved,
        ),
        (WindowsIoFailure::Other, TransportError::Unavailable),
    ];

    for command in commands {
        let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
        for (failure, expected) in failures.clone() {
            assert_eq!(
                convert_scsi_completion(&packet, NativeScsiCompletion::attempted_error(failure),),
                CommandDispatch::CompletionUnknown(expected),
            );
        }
    }
}

/// Validation/allocation failures before DeviceIoControl remain safely retryable as not sent.
#[test]
fn pre_call_win32_failures_are_not_sent_for_every_risk_class() {
    let commands = [
        inquiry(InquiryPage::Standard),
        self_test(),
        unit_reset(),
        write_buffer(0x05, 0x012345, &[]).expect("bounded firmware finalize"),
    ];
    let failures = [
        (WindowsIoFailure::AccessDenied, TransportError::Unavailable),
        (WindowsIoFailure::Busy, TransportError::Unavailable),
        (WindowsIoFailure::Cancelled, TransportError::Unavailable),
        (WindowsIoFailure::TimedOut, TransportError::Timeout),
        (
            WindowsIoFailure::DeviceRemoved,
            TransportError::DeviceRemoved,
        ),
        (WindowsIoFailure::Other, TransportError::Unavailable),
    ];

    for command in commands {
        let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
        for (failure, expected) in failures.clone() {
            assert_eq!(
                convert_scsi_completion(&packet, NativeScsiCompletion::not_attempted(failure),),
                CommandDispatch::NotSent(expected),
            );
        }
    }
}

/// A returned device rejection cannot prove that a mutating operation had no effect.
#[test]
fn mutating_device_rejections_are_completion_unknown() {
    let mut mode_page = vec![0_u8; 13];
    mode_page[0..2].copy_from_slice(&11_u16.to_be_bytes());
    mode_page[8] = 0x31;
    mode_page[9] = 3;
    let commands = vec![
        self_test(),
        led_test(true),
        led_test(false),
        unit_reset(),
        mode_select(&mode_page, false).expect("bounded MODE SELECT"),
        write_buffer(0x04, 0x012345, &[0xA5; 17]).expect("bounded firmware chunk"),
        write_buffer(0x05, 0x012345, &[]).expect("bounded firmware finalize"),
    ];

    for command in commands {
        let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
        let mut sense = vec![0_u8; 18];
        sense[0] = 0x70;
        sense[2] = 0x05;
        sense[7] = 10;

        let check_condition = convert_scsi_completion(
            &packet,
            NativeScsiCompletion::device(0x02, 0, Vec::new(), sense.len(), sense),
        );
        let busy_status = convert_scsi_completion(
            &packet,
            NativeScsiCompletion::device(0x08, 0, Vec::new(), 0, Vec::new()),
        );

        assert!(matches!(
            check_condition,
            CommandDispatch::CompletionUnknown(TransportError::CheckCondition(_))
        ));
        assert_eq!(
            busy_status,
            CommandDispatch::CompletionUnknown(TransportError::Unavailable)
        );
    }
}

/// Exact read-only query commands may retain a device-proven rejection outcome.
#[test]
fn read_only_device_rejections_are_definite() {
    let commands = [
        inquiry(InquiryPage::Standard),
        inquiry(InquiryPage::DeviceIdentification),
        log_sense(0x20).expect("proven LOG page"),
        log_sense(0x21).expect("proven LOG page"),
        mode_sense(0x31).expect("proven MODE page"),
        mode_sense(0x33).expect("proven MODE page"),
        mode_sense(0x34).expect("proven MODE page"),
        security_in(0x0010).expect("proven security selector"),
        security_in(0x0020).expect("proven security selector"),
        security_in(0x0021).expect("proven security selector"),
    ];

    for command in commands {
        let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
        let mut sense = vec![0_u8; 18];
        sense[0] = 0x70;
        sense[2] = 0x05;
        sense[7] = 10;
        let check_condition = convert_scsi_completion(
            &packet,
            NativeScsiCompletion::device(0x02, 0, Vec::new(), sense.len(), sense),
        );
        let rejection = convert_scsi_completion(
            &packet,
            NativeScsiCompletion::device(0x08, 0, Vec::new(), 0, Vec::new()),
        );

        assert_eq!(
            rejection,
            CommandDispatch::DefinitelyRejected(TransportError::Unavailable)
        );
        assert!(matches!(
            check_condition,
            CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(_))
        ));
    }
}

/// CHECK CONDITION remains distinct and carries only bounded parsed sense.
#[test]
fn check_condition_returns_parsed_sense_instead_of_data() {
    let command = log_sense(0x20).expect("proven RDX log page");
    let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
    let mut sense = vec![0_u8; 18];
    sense[0] = 0x70;
    sense[2] = 0x07;
    sense[7] = 10;
    sense[12] = 0x74;
    sense[13] = 0x08;
    let completion = NativeScsiCompletion::device(0x02, 0, Vec::new(), sense.len(), sense);

    let error = parse_scsi_result(&packet, completion).expect_err("CHECK CONDITION");

    let WindowsResultError::CheckCondition(parsed) = error else {
        panic!("expected parsed CHECK CONDITION");
    };
    assert_eq!(parsed.code(), "firmware-signature-error");
}

/// SPTI underruns retain only actual bytes and report the exact residual.
#[test]
fn successful_short_transfer_is_bounded_to_the_reported_length() {
    let command = log_sense(0x20).expect("proven RDX log page");
    let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
    let completion = NativeScsiCompletion::device(0, 200, vec![0xA5; 0xFE], 0, Vec::new());

    let parsed = parse_scsi_result(&packet, completion).expect("valid underrun");

    assert_eq!(parsed.transferred_length(), 200);
    assert_eq!(parsed.residual_length(), 0xFE - 200);
    assert_eq!(parsed.data(), vec![0xA5; 200]);
}

/// GOOD status cannot smuggle contradictory request-sense evidence.
#[test]
fn good_status_rejects_unexpected_sense_bytes() {
    let packet = build_scsi_pass_through(&self_test()).expect("bounded SPTI request");
    let completion = NativeScsiCompletion::device(0, 0, Vec::new(), 8, vec![0; 8]);

    assert_eq!(
        parse_scsi_result(&packet, completion),
        Err(WindowsResultError::UnexpectedSense)
    );
}

/// No-data commands use buffered SPTI and an in-buffer bounded sense region.
#[test]
fn no_data_pass_through_has_pointer_width_safe_offsets() {
    let packet = build_scsi_pass_through(&self_test()).expect("bounded SPTI request");

    assert_eq!(packet.kind(), PassThroughKind::Buffered);
    assert_eq!(packet.data_direction(), SCSI_IOCTL_DATA_UNSPECIFIED);
    assert_eq!(packet.transfer_length(), 0);
    assert_eq!(packet.data_offset(), 0);
    assert_eq!(packet.sense_offset(), packet.header_length());
    assert_eq!(packet.sense_capacity(), WINDOWS_SENSE_CAPACITY);
    assert!(packet.total_control_length() >= packet.sense_offset() + WINDOWS_SENSE_CAPACITY);
}

/// Portable layout arithmetic matches Windows' 32/64-bit SPTI header ABI.
#[test]
fn pass_through_header_size_is_pointer_width_exact_and_aligned() {
    let packet = build_scsi_pass_through(&self_test()).expect("bounded SPTI request");
    let expected = if usize::BITS == 64 { 56 } else { 44 };

    assert_eq!(packet.header_length(), expected);
    assert_eq!(packet.header_length() % std::mem::align_of::<usize>(), 0);
    assert_eq!(packet.sense_offset(), expected);
    assert_eq!(
        packet.total_control_length(),
        expected + WINDOWS_SENSE_CAPACITY
    );
}

/// Data-out commands retain exact offset, payload length, direction, and timeout rounding.
#[test]
fn data_out_layout_and_fractional_timeout_are_exact() {
    let command = write_buffer(0x04, 0x012345, &[0xA5; 17])
        .expect("bounded firmware chunk")
        .with_timeout_ms(1_001)
        .expect("bounded timeout");
    let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");

    assert_eq!(packet.kind(), PassThroughKind::Direct);
    assert_eq!(
        packet.data_direction(),
        rdx_service::platform::windows::SCSI_IOCTL_DATA_OUT
    );
    assert_eq!(packet.transfer_length(), 17);
    assert_eq!(packet.timeout_seconds(), 2);
    assert_eq!(
        packet.cdb(),
        &[0x3B, 0x04, 0, 0x01, 0x23, 0x45, 0, 0, 17, 0]
    );
}

/// Hostile transfer counts and copied lengths are rejected before response creation.
#[test]
fn hostile_transfer_lengths_fail_closed() {
    let packet = build_scsi_pass_through(&log_sense(0x20).expect("proven RDX log page"))
        .expect("bounded SPTI request");

    assert_eq!(
        parse_scsi_result(
            &packet,
            NativeScsiCompletion::device(0, 0xFF, vec![0; 0xFF], 0, Vec::new())
        ),
        Err(WindowsResultError::TransferredLengthOutOfBounds)
    );
    assert_eq!(
        parse_scsi_result(
            &packet,
            NativeScsiCompletion::device(0, 10, vec![0; 9], 0, Vec::new())
        ),
        Err(WindowsResultError::ReturnedDataTooShort)
    );
}

/// A short data-out completion is ambiguous and cannot report operation success.
#[test]
fn short_data_out_transfer_fails_closed() {
    let command = write_buffer(0x04, 0, &[0xA5; 17]).expect("bounded firmware chunk");
    let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
    let completion = NativeScsiCompletion::device(0, 16, Vec::new(), 0, Vec::new());

    assert_eq!(
        parse_scsi_result(&packet, completion.clone()),
        Err(WindowsResultError::ShortDataOut)
    );
    assert_eq!(
        convert_scsi_completion(&packet, completion),
        CommandDispatch::CompletionUnknown(TransportError::DataOutIncomplete)
    );
    assert!(!TransportError::DataOutIncomplete.permits_firmware_retry());
    assert!(TransportError::DataOutIncomplete.is_ambiguous());
}

/// Hostile request-sense lengths never escape the fixed parser boundary.
#[test]
fn hostile_sense_lengths_and_payloads_fail_closed() {
    let packet = build_scsi_pass_through(&self_test()).expect("bounded SPTI request");

    assert_eq!(
        parse_scsi_result(
            &packet,
            NativeScsiCompletion::device(
                0x02,
                0,
                Vec::new(),
                WINDOWS_SENSE_CAPACITY + 1,
                vec![0; WINDOWS_SENSE_CAPACITY],
            )
        ),
        Err(WindowsResultError::SenseLengthOutOfBounds)
    );
    assert_eq!(
        parse_scsi_result(
            &packet,
            NativeScsiCompletion::device(0x02, 0, Vec::new(), 18, vec![0; 17])
        ),
        Err(WindowsResultError::SenseTruncated)
    );
    assert_eq!(
        parse_scsi_result(
            &packet,
            NativeScsiCompletion::device(0x02, 0, Vec::new(), 18, vec![0xFF; 18])
        ),
        Err(WindowsResultError::MalformedSense)
    );
}

/// Hostile candidate text is rejected without reproducing it in the error.
#[test]
fn candidate_normalization_rejects_controls_padding_and_oversize() {
    use rdx_service::platform::windows::WindowsCandidateError;

    for instance in ["", " USBSTOR\\RDX", "USBSTOR\\RDX\n"] {
        assert!(matches!(
            normalize_windows_candidate(1, instance),
            Err(WindowsCandidateError::InvalidInstanceId)
        ));
    }
    assert!(matches!(
        normalize_windows_candidate(1, &"A".repeat(201)),
        Err(WindowsCandidateError::InvalidInstanceId)
    ));
    assert_eq!(
        format!("{:?}", WindowsCandidateError::InvalidInstanceId),
        "InvalidInstanceId"
    );
}

/// Packaged service metadata is demand-started, noninteractive, and claim-free.
#[test]
fn windows_service_metadata_is_least_privilege_and_never_auto_installs() {
    let metadata = include_str!("../resources/windows/openrdx-hardware-service.xml");

    assert!(metadata.contains("startMode=\"demand\""));
    assert!(metadata.contains("account=\"NT AUTHORITY\\LocalService\""));
    assert!(metadata.contains("interactive=\"false\""));
    assert!(metadata.contains("autoInstall=\"false\""));
    assert!(metadata.contains("autoElevate=\"false\""));
    assert!(metadata.contains("hardwareVerified=\"false\""));
    assert!(metadata.contains("serviceControlAccess=\"query-config query-status start\""));
    assert!(metadata.contains("serviceControlAccessMask=\"0x00000015\""));
    assert!(metadata.contains("serviceControlOtherUnprivilegedAccess=\"none\""));
    assert!(metadata.contains("serviceControlCanStop=\"false\""));
    assert!(metadata.contains("serviceControlCanChangeConfig=\"false\""));
    assert!(metadata.contains("serviceControlCanDelete=\"false\""));
    assert!(metadata.contains("servicePidMustMatchCurrentProcess=\"true\""));
    assert!(metadata.contains("servicePidMustRemainStable=\"true\""));
    assert!(metadata.contains("serviceRuntimeTypeMustBeOwnProcess=\"true\""));
    assert!(metadata.contains("serviceConfigMustRemainStable=\"true\""));
    assert!(metadata.contains("serviceBinaryMustMatchCurrentProcess=\"true\""));
    assert!(metadata.contains("serviceTokenUserMustBeLocalService=\"true\""));
    assert!(metadata.contains("processAccess=\"query-limited-information\""));
    assert!(metadata.contains("tokenAccess=\"query\""));
    assert!(metadata.contains("volumeMutationDesiredAccess=\"read-write\""));
    assert!(metadata.contains("volumeMutationControls=\"lock dismount\""));
    assert!(metadata.contains("directAuthorityRequiresElevatedToken=\"true\""));
    assert!(metadata.contains("directAuthorityRequiresExactDeviceAccess=\"true\""));
    for forbidden in [
        "password",
        "secret",
        "LocalSystem",
        "autoInstall=\"true\"",
        "serviceAccountMustMatchRuntime",
    ] {
        assert!(!metadata.contains(forbidden));
    }
}
