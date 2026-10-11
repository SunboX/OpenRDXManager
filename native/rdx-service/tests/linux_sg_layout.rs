// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::platform::PlatformBackend;
use rdx_service::platform::linux::{
    DRIVER_SENSE, DeviceAccessEvidence, LINUX_SENSE_CAPACITY, LinuxBackend, LinuxIoFailure,
    LinuxReadinessFacts, LinuxReadinessIssue, LinuxResultError, NativeSgCompletion,
    SG_DXFER_FROM_DEV, SG_DXFER_NONE, SG_DXFER_TO_DEV, SG_INFO_CHECK, SG_INFO_OK, SgIoStatus,
    build_sg_io, convert_sg_completion, evaluate_linux_readiness, parse_sg_io,
};
use rdx_service::protocol::{
    InquiryPage, inquiry, led_test, log_sense, mode_select, mode_sense, security_in, self_test,
    unit_reset, write_buffer,
};
use rdx_service::transport::{CommandDispatch, TransportError};

/// A data-in packet must preserve every trusted command field used by `SG_IO`.
#[test]
fn sg_io_maps_data_in_cdb_timeout_and_lengths() {
    let command = log_sense(0x21).expect("proven RDX log page");
    let packet = build_sg_io(&command).expect("bounded SG_IO packet");

    assert_eq!(packet.interface_id(), i32::from(b'S'));
    assert_eq!(packet.direction(), SG_DXFER_FROM_DEV);
    assert_eq!(packet.cdb(), &[0x4D, 0, 0x21, 0, 0, 0, 0, 0, 0xFE, 0]);
    assert_eq!(packet.command_length(), 10);
    assert_eq!(packet.transfer_length(), 0xFE);
    assert_eq!(packet.timeout_ms(), 30_000);
    assert_eq!(packet.sense_capacity(), LINUX_SENSE_CAPACITY);
}

/// Factory-record reads retain exact data-in lengths and readonly rejection certainty.
#[test]
fn manufacturing_reads_preserve_exact_linux_completion_contract() {
    for command in [
        rdx_service::protocol::openrdx_manufacturing_record_first(),
        rdx_service::protocol::openrdx_manufacturing_record_second(),
    ] {
        let packet = build_sg_io(&command).unwrap();
        assert_eq!(packet.direction(), SG_DXFER_FROM_DEV);
        assert_eq!(packet.transfer_length(), 128);
        let good =
            NativeSgCompletion::device(SgIoStatus::good(), 0, vec![0xa5; 128], 0, Vec::new());
        let response = convert_sg_completion(&packet, good);
        assert_eq!(response.response().unwrap().data(), [0xa5; 128]);
        let mut sense = vec![0; 18];
        sense[0] = 0x70;
        sense[2] = 5;
        sense[7] = 10;
        sense[12] = 0x24;
        let rejected = NativeSgCompletion::device(
            SgIoStatus::new(2, 1, 0, 0, DRIVER_SENSE, SG_INFO_CHECK),
            128,
            vec![0; 128],
            sense.len(),
            sense,
        );
        assert!(matches!(
            convert_sg_completion(&packet, rejected),
            CommandDispatch::DefinitelyRejected(_)
        ));
    }
}

/// No-data and data-out packets use the exact signed Linux direction constants.
#[test]
fn sg_io_maps_none_and_data_out_without_direction_guessing() {
    let none = build_sg_io(&self_test()).expect("bounded no-data packet");
    let output =
        build_sg_io(&write_buffer(0x04, 0x012345, &[0xA5; 17]).expect("bounded firmware chunk"))
            .expect("bounded data-out packet");

    assert_eq!(none.direction(), SG_DXFER_NONE);
    assert_eq!(none.transfer_length(), 0);
    assert_eq!(output.direction(), SG_DXFER_TO_DEV);
    assert_eq!(output.transfer_length(), 17);
}

/// The pointer-width layout mirrors Linux's public `sg_io_hdr_t` ABI.
#[test]
fn sg_io_header_size_is_pointer_width_exact() {
    let packet = build_sg_io(&self_test()).expect("bounded SG_IO packet");
    let expected = if usize::BITS == 64 { 88 } else { 64 };

    assert_eq!(packet.header_length(), expected);
    assert_eq!(packet.header_length() % std::mem::align_of::<usize>(), 0);
}

/// A non-negative underrun retains only the bytes proven transferred.
#[test]
fn successful_residual_is_subtracted_and_data_is_truncated() {
    let packet =
        build_sg_io(&log_sense(0x20).expect("proven RDX log page")).expect("bounded SG_IO packet");
    let completion =
        NativeSgCompletion::device(SgIoStatus::good(), 54, vec![0xA5; 0xFE], 0, Vec::new());

    let parsed = parse_sg_io(&packet, completion).expect("valid SG underrun");

    assert_eq!(parsed.transferred_length(), 200);
    assert_eq!(parsed.residual_length(), 54);
    assert_eq!(parsed.data(), vec![0xA5; 200]);
}

/// Signed residuals outside the request cannot wrap into a successful length.
#[test]
fn hostile_signed_residuals_fail_closed() {
    let packet =
        build_sg_io(&log_sense(0x20).expect("proven RDX log page")).expect("bounded SG_IO packet");

    assert_eq!(
        parse_sg_io(
            &packet,
            NativeSgCompletion::device(SgIoStatus::good(), -1, vec![0; 0xFE], 0, Vec::new(),),
        ),
        Err(LinuxResultError::NegativeResidual),
    );
    assert_eq!(
        parse_sg_io(
            &packet,
            NativeSgCompletion::device(SgIoStatus::good(), 0xFF, vec![0; 0xFE], 0, Vec::new(),),
        ),
        Err(LinuxResultError::ResidualOutOfBounds),
    );
}

/// Host, driver, and info failures remain distinct from the SCSI status byte.
#[test]
fn host_driver_and_info_statuses_are_checked_exactly() {
    let packet = build_sg_io(&self_test()).expect("bounded SG_IO packet");

    assert_eq!(
        parse_sg_io(
            &packet,
            NativeSgCompletion::device(
                SgIoStatus::new(0, 0, 0, 0x03, 0, SG_INFO_CHECK),
                0,
                Vec::new(),
                0,
                Vec::new(),
            ),
        ),
        Err(LinuxResultError::HostStatus(0x03)),
    );
    assert_eq!(
        parse_sg_io(
            &packet,
            NativeSgCompletion::device(
                SgIoStatus::new(0, 0, 0, 0, 0x04, SG_INFO_CHECK),
                0,
                Vec::new(),
                0,
                Vec::new(),
            ),
        ),
        Err(LinuxResultError::DriverStatus(0x04)),
    );
    assert_eq!(
        parse_sg_io(
            &packet,
            NativeSgCompletion::device(
                SgIoStatus::new(0, 0, 0, 0, 0, SG_INFO_CHECK),
                0,
                Vec::new(),
                0,
                Vec::new(),
            ),
        ),
        Err(LinuxResultError::InconsistentInfo),
    );
}

/// CHECK CONDITION requires the exact status/info/driver-sense shape and bounded sense.
#[test]
fn check_condition_returns_only_bounded_parsed_sense() {
    let packet =
        build_sg_io(&log_sense(0x20).expect("proven RDX log page")).expect("bounded SG_IO packet");
    let mut sense = vec![0_u8; 18];
    sense[0] = 0x70;
    sense[2] = 0x07;
    sense[7] = 10;
    sense[12] = 0x74;
    sense[13] = 0x08;
    let completion = NativeSgCompletion::device(
        SgIoStatus::new(0x02, 0x01, 0, 0, DRIVER_SENSE, SG_INFO_CHECK),
        0xFE,
        vec![0; 0xFE],
        sense.len(),
        sense,
    );

    let error = parse_sg_io(&packet, completion).expect_err("CHECK CONDITION");
    let LinuxResultError::CheckCondition(parsed) = error else {
        panic!("expected parsed CHECK CONDITION");
    };
    assert_eq!(parsed.code(), "firmware-signature-error");
}

/// GOOD status cannot carry sense or a contradictory info check bit.
#[test]
fn good_status_rejects_unexpected_sense_and_info() {
    let packet = build_sg_io(&self_test()).expect("bounded SG_IO packet");

    assert_eq!(
        parse_sg_io(
            &packet,
            NativeSgCompletion::device(SgIoStatus::good(), 0, Vec::new(), 8, vec![0; 8],),
        ),
        Err(LinuxResultError::UnexpectedSense),
    );
}

/// A successful data-out ioctl with a residual is still an ambiguous short write.
#[test]
fn short_data_out_never_reports_success() {
    let packet = build_sg_io(&write_buffer(0x04, 0, &[0xA5; 17]).expect("bounded firmware chunk"))
        .expect("bounded SG_IO packet");
    let completion = NativeSgCompletion::device(SgIoStatus::good(), 1, Vec::new(), 0, Vec::new());

    assert_eq!(
        parse_sg_io(&packet, completion),
        Err(LinuxResultError::ShortDataOut),
    );
}

/// Once `ioctl(SG_IO)` was invoked, every syscall failure is completion-unknown.
#[test]
fn attempted_linux_failures_are_never_not_sent() {
    let commands = [
        inquiry(InquiryPage::Standard),
        self_test(),
        unit_reset(),
        write_buffer(0x05, 0x012345, &[]).expect("bounded firmware finalize"),
    ];
    let failures = [
        (LinuxIoFailure::AccessDenied, TransportError::Unavailable),
        (LinuxIoFailure::Busy, TransportError::Unavailable),
        (LinuxIoFailure::Interrupted, TransportError::Unavailable),
        (LinuxIoFailure::TimedOut, TransportError::Timeout),
        (LinuxIoFailure::DeviceRemoved, TransportError::DeviceRemoved),
        (LinuxIoFailure::Other, TransportError::Unavailable),
    ];

    for command in commands {
        let packet = build_sg_io(&command).expect("bounded SG_IO packet");
        for (failure, expected) in failures.clone() {
            assert_eq!(
                convert_sg_completion(&packet, NativeSgCompletion::attempted_error(failure)),
                CommandDispatch::CompletionUnknown(expected),
            );
        }
    }
}

/// Validation/allocation failures before the ioctl remain proven not sent.
#[test]
fn pre_call_linux_failures_are_not_sent() {
    let packet = build_sg_io(&self_test()).expect("bounded SG_IO packet");

    assert_eq!(
        convert_sg_completion(
            &packet,
            NativeSgCompletion::not_attempted(LinuxIoFailure::Other),
        ),
        CommandDispatch::NotSent(TransportError::Unavailable),
    );
}

/// Exact read-only commands may retain a device-proven rejection outcome.
#[test]
fn only_read_only_device_rejections_are_definite() {
    let mut mode_page = vec![0_u8; 13];
    mode_page[0..2].copy_from_slice(&11_u16.to_be_bytes());
    mode_page[8] = 0x31;
    mode_page[9] = 3;
    let read_only = [
        inquiry(InquiryPage::Standard),
        log_sense(0x21).expect("proven LOG page"),
        mode_sense(0x31).expect("proven MODE page"),
        security_in(0x0010).expect("proven selector"),
    ];
    let mutating = vec![
        self_test(),
        led_test(true),
        unit_reset(),
        mode_select(&mode_page, false).expect("bounded MODE SELECT"),
        write_buffer(0x04, 0, &[0xA5]).expect("bounded firmware chunk"),
    ];

    for command in read_only {
        let packet = build_sg_io(&command).expect("bounded SG_IO packet");
        let completion = NativeSgCompletion::device(
            SgIoStatus::new(0x08, 0x04, 0, 0, 0, SG_INFO_CHECK),
            i32::try_from(packet.transfer_length()).expect("small request"),
            Vec::new(),
            0,
            Vec::new(),
        );
        assert_eq!(
            convert_sg_completion(&packet, completion),
            CommandDispatch::DefinitelyRejected(TransportError::Unavailable),
        );
    }
    for command in mutating {
        let packet = build_sg_io(&command).expect("bounded SG_IO packet");
        let completion = NativeSgCompletion::device(
            SgIoStatus::new(0x08, 0x04, 0, 0, 0, SG_INFO_CHECK),
            i32::try_from(packet.transfer_length()).expect("small request"),
            Vec::new(),
            0,
            Vec::new(),
        );
        assert_eq!(
            convert_sg_completion(&packet, completion),
            CommandDispatch::CompletionUnknown(TransportError::Unavailable),
        );
    }
}

/// Readiness reports the first concrete missing prerequisite instead of availability.
#[test]
fn readiness_matrix_distinguishes_linux_authority_failures() {
    let ready = LinuxReadinessFacts::new(
        true,
        true,
        true,
        true,
        DeviceAccessEvidence::ReadWrite,
        true,
        true,
        true,
        true,
    );
    let cases = [
        (
            LinuxReadinessFacts::new(
                false,
                true,
                true,
                true,
                DeviceAccessEvidence::ReadWrite,
                true,
                true,
                true,
                true,
            ),
            LinuxReadinessIssue::SysfsUnavailable,
        ),
        (
            LinuxReadinessFacts::new(
                true,
                false,
                true,
                true,
                DeviceAccessEvidence::ReadWrite,
                true,
                true,
                true,
                true,
            ),
            LinuxReadinessIssue::UdevRulesMissing,
        ),
        (
            LinuxReadinessFacts::new(
                true,
                true,
                false,
                true,
                DeviceAccessEvidence::ReadWrite,
                true,
                true,
                true,
                true,
            ),
            LinuxReadinessIssue::IpcGroupMissing,
        ),
        (
            LinuxReadinessFacts::new(
                true,
                true,
                true,
                false,
                DeviceAccessEvidence::ReadWrite,
                true,
                true,
                true,
                true,
            ),
            LinuxReadinessIssue::CurrentIpcGroupMembershipMissing,
        ),
        (
            LinuxReadinessFacts::new(
                true,
                true,
                true,
                true,
                DeviceAccessEvidence::ReadWrite,
                false,
                true,
                true,
                true,
            ),
            LinuxReadinessIssue::PolkitPolicyMissing,
        ),
        (
            LinuxReadinessFacts::new(
                true,
                true,
                true,
                true,
                DeviceAccessEvidence::ReadWrite,
                true,
                false,
                true,
                true,
            ),
            LinuxReadinessIssue::ServiceNotInstalled,
        ),
        (
            LinuxReadinessFacts::new(
                true,
                true,
                true,
                true,
                DeviceAccessEvidence::ReadWrite,
                true,
                true,
                false,
                true,
            ),
            LinuxReadinessIssue::ServiceNotRunning,
        ),
        (
            LinuxReadinessFacts::new(
                true,
                true,
                true,
                true,
                DeviceAccessEvidence::ReadWrite,
                true,
                true,
                true,
                false,
            ),
            LinuxReadinessIssue::CurrentProcessUnauthorized,
        ),
    ];

    for (facts, expected) in cases {
        let report = evaluate_linux_readiness(facts);
        assert_eq!(report.issue(), expected);
        assert!(!report.capabilities().transport_available());
        assert!(!report.capabilities().privileged());
    }

    let report = evaluate_linux_readiness(ready);
    assert_eq!(report.issue(), LinuxReadinessIssue::ReadyHardwareUnverified);
    assert!(report.capabilities().discovery_available());
    assert!(report.capabilities().transport_available());
    assert!(report.capabilities().privileged());
    assert!(!report.capabilities().hardware_verified());

    for access in [
        DeviceAccessEvidence::NoCandidate,
        DeviceAccessEvidence::Denied,
    ] {
        let report = evaluate_linux_readiness(LinuxReadinessFacts::new(
            true, true, true, true, access, true, true, true, true,
        ));
        assert_eq!(report.issue(), LinuxReadinessIssue::ReadyHardwareUnverified);
        assert!(report.capabilities().discovery_available());
        assert!(report.capabilities().transport_available());
        assert!(report.capabilities().privileged());
        assert!(!report.capabilities().hardware_verified());
    }
}

/// Shipped udev metadata actively reserves only the proven RDX VID/PID for root service use.
#[test]
fn shipped_udev_rule_is_active_exact_and_service_only() {
    let rules = include_str!("../resources/linux/70-openrdx.rules");
    let active_lines = rules
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();

    assert_eq!(active_lines.len(), 1);
    let rule = active_lines[0];
    assert!(rule.contains("ATTRS{idVendor}==\"1a5a\""));
    assert!(rule.contains("ATTRS{idProduct}==\"0006\""));
    assert!(rule.contains("OWNER=\"root\""));
    assert!(rule.contains("GROUP=\"root\""));
    assert!(rule.contains("MODE=\"0600\""));
    assert!(!rule.contains("GROUP=\"openrdx\""));
    assert!(!rule.contains("uaccess"));
    assert!(!rules.contains("MODE=\"0666\""));
    assert!(!rules.contains("MODE:=\"0666\""));
}

/// The packaged polkit metadata names one narrow action and grants no default access.
#[test]
fn shipped_polkit_policy_is_narrow_and_noninteractive_by_default() {
    let policy = include_str!("../resources/linux/org.openrdx.hardware.policy");

    assert!(policy.contains("<action id=\"org.openrdx.hardware.manage\">"));
    assert!(policy.contains("<allow_any>no</allow_any>"));
    assert!(policy.contains("<allow_inactive>no</allow_inactive>"));
    assert!(policy.contains("<allow_active>auth_admin</allow_active>"));
    assert!(!policy.contains("auth_admin_keep"));
    assert_eq!(policy.matches("<action id=").count(), 1);
    assert!(!policy.contains("<allow_any>yes</allow_any>"));
    for forbidden in ["password", "secret", "token", "credential"] {
        assert!(!policy.to_ascii_lowercase().contains(forbidden));
    }
}

/// The Linux backend constructor cannot activate on a non-Linux target.
#[cfg(not(target_os = "linux"))]
#[test]
fn native_linux_backend_is_target_gated_off_linux() {
    let backend = LinuxBackend::native();

    assert!(!backend.capabilities().discovery_available());
    assert!(!backend.capabilities().transport_available());
    assert!(!backend.capabilities().privileged());
    assert!(!backend.capabilities().hardware_verified());
}

/// Constants retain the signed SG v3 ABI values instead of unsigned aliases.
#[test]
fn sg_direction_and_info_constants_match_the_linux_abi() {
    assert_eq!(SG_DXFER_NONE, -1);
    assert_eq!(SG_DXFER_TO_DEV, -2);
    assert_eq!(SG_DXFER_FROM_DEV, -3);
    assert_eq!(SG_INFO_OK, 0);
    assert_eq!(SG_INFO_CHECK, 1);
}
