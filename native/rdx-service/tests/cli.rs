// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end and feature-gated fixture coverage for the `rdxctl` contract.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
#[cfg(unix)]
use std::process::Stdio;
use std::process::{Command, Output};

use rdx_service::service::cli::{self, CliExit};

#[cfg(feature = "fixtures")]
use rdx_service::host::HostOperationError;
#[cfg(feature = "fixtures")]
use rdx_service::model::CapabilityState;
#[cfg(feature = "fixtures")]
use rdx_service::operations::HostEjectPolicy;
#[cfg(feature = "fixtures")]
use rdx_service::protocol::SenseData;
#[cfg(feature = "fixtures")]
use rdx_service::service::cli::fixtures::{FixtureBackend, run_with_fixture};
#[cfg(feature = "fixtures")]
use rdx_service::transport::{CommandDispatch, TransportError};

/// Returns Cargo's exact test-built `rdxctl` executable.
fn rdxctl() -> &'static str {
    env!("CARGO_BIN_EXE_rdxctl")
}

/// Runs the real test-built binary with the supplied operating-system arguments.
fn run<I, S>(arguments: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(rdxctl())
        .args(arguments)
        .output()
        .expect("rdxctl test process starts")
}

/// Returns stdout as strict UTF-8 because every CLI response is ASCII JSON or text.
fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).expect("rdxctl stdout is UTF-8")
}

/// Returns stderr as strict UTF-8 because diagnostics never echo hostile bytes.
fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).expect("rdxctl stderr is UTF-8")
}

/// Writer whose buffered bytes succeed but whose required final flush fails.
#[derive(Default)]
struct FlushFailureWriter {
    bytes: Vec<u8>,
}

impl Write for FlushFailureWriter {
    /// Retains written bytes so the test isolates finalization from writing.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Simulates an output channel that fails only when completion is finalized.
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "controlled flush failure",
        ))
    }
}

/// Proves help is stable, bounded, ANSI-free, and successful.
#[test]
fn help_is_stable_and_successful() {
    let output = run(["--help"]);

    assert_eq!(output.status.code(), Some(CliExit::Success.code()));
    assert_eq!(
        stdout(&output),
        "rdxctl - high-level OpenRDXManager device control\n\nUSAGE:\n  rdxctl --help\n  rdxctl --version\n  rdxctl --scan\n  rdxctl --eject <opaque-target> [--force]\n\nOPTIONS:\n  --help      Show this help without accessing hardware.\n  --version   Show the package version without accessing hardware.\n  --scan      Scan through the native service backend.\n  --eject     Eject one bounded opaque rdx: target.\n  --force     Change host eject policy and warn about cached-data risk.\n"
    );
    assert!(stderr(&output).is_empty());
    assert!(output.stdout.len() < 1_024);
    assert!(!output.stdout.contains(&0x1b));
}

/// Proves version output comes from Cargo package metadata and remains backend-free text.
#[test]
fn version_comes_from_the_package() {
    let output = run(["--version"]);

    assert_eq!(output.status.code(), Some(CliExit::Success.code()));
    assert_eq!(
        stdout(&output),
        concat!("rdxctl ", env!("CARGO_PKG_VERSION"), "\n")
    );
    assert!(stderr(&output).is_empty());
}

/// Proves dev stdio cannot claim privileged native service authority.
#[test]
fn eject_without_a_platform_adapter_fails_as_a_capability_rejection() {
    let output = run(["--eject", "rdx:fixture-01"]);

    assert_eq!(output.status.code(), Some(CliExit::Prerequisite.code()));
    assert!(stdout(&output).is_empty());
    assert_eq!(
        stderr(&output),
        "{\"code\":\"insufficient-permission\",\"reason\":\"privileged-service-unavailable\",\"status\":\"error\"}\n"
    );
    assert!(!stderr(&output).contains("rdx:fixture-01"));
}

/// Proves force alone is rejected before any device access, as required by the plan.
#[test]
fn force_without_eject_is_rejected_without_device_access() {
    let output = run(["--force"]);

    assert_eq!(output.status.code(), Some(CliExit::Usage.code()));
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("--force requires --eject"));
}

/// Proves a valid forced action warns even when the capability gate rejects later.
#[test]
fn forced_eject_always_warns_before_a_later_capability_failure() {
    let output = run(["--force", "--eject", "RDX:fixture-01"]);

    assert_eq!(output.status.code(), Some(CliExit::Prerequisite.code()));
    assert!(stdout(&output).is_empty());
    assert_eq!(
        stderr(&output),
        "{\"code\":\"cached-data-risk\",\"level\":\"warning\",\"message\":\"forced eject can lose cached data\"}\n{\"code\":\"insufficient-permission\",\"reason\":\"privileged-service-unavailable\",\"status\":\"error\"}\n"
    );
    assert!(!stderr(&output).contains("RDX:fixture-01"));
}

/// Proves every ambiguous, duplicate, combined, unknown, or positional form is usage error 2.
#[test]
fn parser_rejects_every_noncanonical_command_shape() {
    let cases: &[&[&str]] = &[
        &[],
        &["--help", "--version"],
        &["--help", "--help"],
        &["--version", "--version"],
        &["--scan", "--scan"],
        &["--scan", "extra"],
        &["--scan", "--force"],
        &["--eject"],
        &["--eject", "rdx:a", "--eject", "rdx:b"],
        &["--eject", "rdx:a", "extra"],
        &["--eject=rdx:a"],
        &["--unknown"],
        &["-h"],
        &["-sf"],
        &["--"],
    ];

    for arguments in cases {
        let output = run(*arguments);
        assert_eq!(
            output.status.code(),
            Some(CliExit::Usage.code()),
            "arguments {arguments:?}"
        );
        assert!(stdout(&output).is_empty(), "arguments {arguments:?}");
        assert!(output.stderr.len() <= 256, "arguments {arguments:?}");
        assert!(!output.stderr.contains(&0x1b), "arguments {arguments:?}");
    }
}

/// Proves raw paths, controls, Unicode, empty values, and oversized targets are rejected.
#[test]
fn target_is_opaque_ascii_and_strictly_bounded() {
    let oversized = format!("rdx:{}", "a".repeat(125));
    let very_long = format!("rdx:{}", "z".repeat(16_384));
    let invalid = [
        OsString::from(""),
        OsString::from("/dev/disk4"),
        OsString::from(r"C:\\PhysicalDrive0"),
        OsString::from("../../device"),
        OsString::from("rdx:control\nvalue"),
        OsString::from("rdx:escape\u{1b}value"),
        OsString::from("rdx:gerät"),
        OsString::from(oversized),
        OsString::from(very_long),
    ];

    for target in invalid {
        let output = run([OsString::from("--eject"), target.clone()]);
        assert_eq!(
            output.status.code(),
            Some(CliExit::Usage.code()),
            "target {target:?}"
        );
        assert!(stdout(&output).is_empty());
        assert!(output.stderr.len() <= 256);
        if !target.is_empty() {
            assert!(
                !output
                    .stderr
                    .windows(target.len())
                    .any(|bytes| bytes == target.as_encoded_bytes())
            );
        }
    }

    let maximum = format!("rdx:{}", "a".repeat(124));
    let output = run(["--eject", &maximum]);
    assert_eq!(output.status.code(), Some(CliExit::Prerequisite.code()));
    assert!(!stderr(&output).contains(&maximum));
}

/// Proves a hostile but syntactically valid target is never repeated in diagnostics.
#[test]
fn diagnostics_redact_valid_targets_and_remain_bounded() {
    let target = "rdx:secret-token-that-must-not-leak";
    let output = run(["--eject", target, "--force"]);

    assert_eq!(output.status.code(), Some(CliExit::Prerequisite.code()));
    assert!(stdout(&output).is_empty());
    assert!(output.stderr.len() <= 512);
    assert!(!stderr(&output).contains(target));
    assert!(!output.stderr.contains(&0x1b));
}

/// Proves non-UTF-8 process arguments are rejected without a panic on Unix hosts.
#[cfg(unix)]
#[test]
fn non_utf8_argument_is_a_bounded_usage_failure() {
    use std::os::unix::ffi::OsStringExt;

    let output = run([OsString::from_vec(vec![0xff, 0xfe])]);

    assert_eq!(output.status.code(), Some(CliExit::Usage.code()));
    assert_ne!(output.status.code(), Some(101));
    assert!(stdout(&output).is_empty());
    assert!(output.stderr.len() <= 256);
}

/// Proves a successful write is not reported until the output channel flushes.
#[test]
fn output_flush_failure_maps_to_service_host_exit() {
    let mut output = FlushFailureWriter::default();
    let mut diagnostics = Vec::new();

    let exit = cli::run([OsString::from("--help")], &mut output, &mut diagnostics);

    assert_eq!(exit, CliExit::ServiceHost);
    assert!(!output.bytes.is_empty());
    assert!(diagnostics.is_empty());
}

/// Proves a real broken stdout pipe is surfaced through Rust `Write` as exit 3.
#[cfg(unix)]
#[test]
fn real_process_broken_stdout_pipe_maps_to_service_host_exit() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let (reader, writer) = UnixStream::pair().expect("local socket pair");
    drop(reader);
    let writer: OwnedFd = writer.into();
    let output = Command::new(rdxctl())
        .arg("--help")
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .expect("rdxctl test process starts");

    assert_eq!(output.status.code(), Some(CliExit::ServiceHost.code()));
    assert!(output.stderr.is_empty());
}

/// Documents Rust std's Unix EBADF compatibility behavior for read-only stdout.
#[cfg(unix)]
#[test]
fn real_process_read_only_stdout_is_not_reported_by_rust_write() {
    let temporary = tempfile::NamedTempFile::new().expect("temporary output path");
    let read_only = std::fs::File::open(temporary.path()).expect("read-only descriptor");
    let status = Command::new(rdxctl())
        .arg("--help")
        .stdout(Stdio::from(read_only))
        .stderr(Stdio::null())
        .spawn()
        .expect("rdxctl test process starts");
    let status = status
        .wait_with_output()
        .expect("rdxctl test process exits")
        .status;

    assert_eq!(status.code(), Some(CliExit::Success.code()));
    assert_eq!(
        std::fs::metadata(temporary.path())
            .expect("temporary metadata")
            .len(),
        0
    );
}

/// Documents the same Rust std EBADF behavior for a truly closed Unix stdout.
#[cfg(unix)]
#[test]
fn real_process_closed_stdout_is_not_reported_by_rust_write() {
    let status = Command::new("sh")
        .args([
            "-c",
            "exec 1>&-; exec \"$1\" --help",
            "rdxctl-closed-stdout",
            rdxctl(),
        ])
        .stderr(Stdio::null())
        .status()
        .expect("shell starts rdxctl with closed stdout");

    assert_eq!(status.code(), Some(CliExit::Success.code()));
}

/// Documents Rust std's same EBADF behavior for read-only diagnostic output.
#[cfg(unix)]
#[test]
fn real_process_read_only_stderr_is_not_reported_by_rust_write() {
    let temporary = tempfile::NamedTempFile::new().expect("temporary diagnostic path");
    let read_only = std::fs::File::open(temporary.path()).expect("read-only descriptor");
    let status = Command::new(rdxctl())
        .arg("--unknown")
        .stdout(Stdio::null())
        .stderr(Stdio::from(read_only))
        .status()
        .expect("rdxctl test process starts");

    assert_eq!(status.code(), Some(CliExit::Usage.code()));
    assert_eq!(
        std::fs::metadata(temporary.path())
            .expect("temporary metadata")
            .len(),
        0
    );
}

/// Documents Rust std's same EBADF behavior for truly closed Unix stderr.
#[cfg(unix)]
#[test]
fn real_process_closed_stderr_is_not_reported_by_rust_write() {
    let status = Command::new("sh")
        .args([
            "-c",
            "exec 2>&-; exec \"$1\" --unknown",
            "rdxctl-closed-stderr",
            rdxctl(),
        ])
        .stdout(Stdio::null())
        .status()
        .expect("shell starts rdxctl with closed stderr");

    assert_eq!(status.code(), Some(CliExit::Usage.code()));
}

/// Proves help and version never instantiate even an injected high-level backend.
#[cfg(feature = "fixtures")]
#[test]
fn informational_commands_do_not_access_an_injected_backend() {
    for argument in ["--help", "--version"] {
        let mut backend = FixtureBackend::default();
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let exit = run_with_fixture(
            [OsString::from(argument)],
            &mut backend,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(exit, CliExit::Success);
        assert_eq!(backend.access_count(), 0);
    }
}

/// Returns one complete fixed-format generic CHECK CONDITION fixture.
#[cfg(feature = "fixtures")]
fn check_condition() -> SenseData {
    SenseData::parse(&[0x70, 0, 0x05, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x20, 0])
        .expect("complete fixed-format sense")
}

/// Runs one safe fixture eject and returns its real CLI outcome and channels.
#[cfg(feature = "fixtures")]
fn run_safe_fixture_eject(backend: &mut FixtureBackend) -> (CliExit, Vec<u8>, Vec<u8>) {
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let exit = run_with_fixture(
        [OsString::from("--eject"), OsString::from("rdx:fixture")],
        backend,
        &mut output,
        &mut diagnostics,
    );
    (exit, output, diagnostics)
}

/// Returns every sanitized host error with its pre-dispatch exit classification.
#[cfg(feature = "fixtures")]
fn host_errors_with_pre_dispatch_exits() -> [(HostOperationError, CliExit); 10] {
    [
        (HostOperationError::DeviceUnavailable, CliExit::ServiceHost),
        (
            HostOperationError::ReconnectTimeout,
            CliExit::PartialOrAmbiguous,
        ),
        (
            HostOperationError::CapabilityUnavailable,
            CliExit::Prerequisite,
        ),
        (HostOperationError::Ambiguous, CliExit::PartialOrAmbiguous),
        (
            HostOperationError::DeviceIdentityChanged,
            CliExit::Prerequisite,
        ),
        (
            HostOperationError::ProductFamilyChanged,
            CliExit::Prerequisite,
        ),
        (
            HostOperationError::StaleSessionGeneration,
            CliExit::Prerequisite,
        ),
        (HostOperationError::InactiveSession, CliExit::Prerequisite),
        (
            HostOperationError::AdapterPanic,
            CliExit::PartialOrAmbiguous,
        ),
        (
            HostOperationError::RecoveryAlreadyArmed,
            CliExit::ServiceHost,
        ),
    ]
}

/// Proves scan obtains its empty result from the shared high-level backend.
#[cfg(feature = "fixtures")]
#[test]
fn injected_scan_calls_only_the_high_level_scan_boundary() {
    let mut backend = FixtureBackend::empty_inventory();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [OsString::from("--scan")],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::Success);
    assert_eq!(backend.access_count(), 1);
    assert_eq!(backend.scan_count(), 1);
    assert_eq!(backend.start_count(), 0);
    assert_eq!(
        std::str::from_utf8(&output).expect("fixture stdout"),
        "{\"command\":\"scan\",\"devices\":[],\"hardwareVerified\":false,\"status\":\"ok\"}\n"
    );
    assert!(diagnostics.is_empty());
}

/// Proves safe eject runs through fresh inventory, exact ownership, and readback.
#[cfg(feature = "fixtures")]
#[test]
fn injected_safe_eject_uses_shared_revisioned_lifecycle() {
    let target = "rdx:fixture";
    let mut backend = FixtureBackend::default();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [OsString::from("--eject"), OsString::from(target)],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::Success);
    assert_eq!(backend.scan_count(), 1);
    assert_eq!(backend.start_count(), 1);
    assert_eq!(backend.refresh_count(), 1);
    assert_eq!(backend.unmount_count(), 1);
    assert_eq!(backend.eject_count(), 1);
    assert_eq!(backend.readback_count(), 1);
    assert_eq!(backend.policies(), &[HostEjectPolicy::Safe]);
    assert_eq!(
        std::str::from_utf8(&output).expect("fixture stdout"),
        "{\"command\":\"eject\",\"status\":\"ok\"}\n"
    );
    assert!(diagnostics.is_empty());
    assert!(
        !output
            .windows(target.len())
            .any(|window| window == target.as_bytes())
    );
}

/// Proves force selects only the typed forced host-cache policy and still reads back.
#[cfg(feature = "fixtures")]
#[test]
fn injected_force_changes_only_host_cache_policy() {
    let mut backend = FixtureBackend::default();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [
            OsString::from("--eject"),
            OsString::from("rdx:fixture"),
            OsString::from("--force"),
        ],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::Success);
    assert_eq!(backend.unmount_count(), 0);
    assert_eq!(backend.eject_count(), 1);
    assert_eq!(backend.readback_count(), 1);
    assert_eq!(backend.policies(), &[HostEjectPolicy::Forced]);
    assert!(
        std::str::from_utf8(&diagnostics)
            .expect("fixture diagnostics")
            .contains("cached-data-risk")
    );
}

/// Proves an opaque target must exist in the fresh shared inventory before dispatch.
#[cfg(feature = "fixtures")]
#[test]
fn injected_eject_rejects_target_absent_from_fresh_inventory() {
    let mut backend = FixtureBackend::default();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [OsString::from("--eject"), OsString::from("rdx:other")],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::Prerequisite);
    assert_eq!(backend.scan_count(), 1);
    assert_eq!(backend.start_count(), 0);
    assert_eq!(backend.eject_count(), 0);
    assert!(output.is_empty());
    assert!(
        !std::str::from_utf8(&diagnostics)
            .expect("fixture diagnostics")
            .contains("rdx:other")
    );
}

/// Proves force cannot bypass the operation's fresh media-presence gate.
#[cfg(feature = "fixtures")]
#[test]
fn injected_force_cannot_bypass_fresh_media_gate() {
    let mut backend = FixtureBackend::without_media();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [
            OsString::from("--eject"),
            OsString::from("rdx:fixture"),
            OsString::from("--force"),
        ],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::Prerequisite);
    assert_eq!(backend.refresh_count(), 0);
    assert_eq!(backend.eject_count(), 0);
    assert_eq!(backend.readback_count(), 0);
    assert!(output.is_empty());
}

/// Proves a session revision changed after inventory cannot reach host eject.
#[cfg(feature = "fixtures")]
#[test]
fn injected_eject_rejects_identity_changed_after_inventory() {
    let mut backend = FixtureBackend::with_changed_session_revision();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [OsString::from("--eject"), OsString::from("rdx:fixture")],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::Prerequisite);
    assert_eq!(backend.scan_count(), 1);
    assert_eq!(backend.start_count(), 1);
    assert_eq!(backend.refresh_count(), 1);
    assert_eq!(backend.eject_count(), 0);
    assert!(output.is_empty());
}

/// Proves shared capability admission rejects force before any operation starts.
#[cfg(feature = "fixtures")]
#[test]
fn injected_force_obeys_fresh_capability_gate() {
    let mut backend = FixtureBackend::with_force_capability(CapabilityState::HardwareUnverified);
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [
            OsString::from("--eject"),
            OsString::from("rdx:fixture"),
            OsString::from("--force"),
        ],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::Prerequisite);
    assert_eq!(backend.scan_count(), 1);
    assert_eq!(backend.start_count(), 0);
    assert_eq!(backend.eject_count(), 0);
    assert!(
        std::str::from_utf8(&diagnostics)
            .expect("fixture diagnostics")
            .contains("cached-data-risk")
    );
}

/// Proves a backend cannot manufacture CLI success without departure evidence.
#[cfg(feature = "fixtures")]
#[test]
fn bare_success_terminal_without_eject_readback_is_rejected() {
    let mut backend = FixtureBackend::bare_success_without_readback();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let exit = run_with_fixture(
        [OsString::from("--eject"), OsString::from("rdx:fixture")],
        &mut backend,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(exit, CliExit::PartialOrAmbiguous);
    assert_eq!(backend.eject_count(), 0);
    assert_eq!(backend.readback_count(), 0);
    assert!(output.is_empty());
}

/// Proves exit classes derive from actual lifecycle and dispatch evidence.
#[cfg(feature = "fixtures")]
#[test]
fn operation_evidence_maps_to_stable_exit_codes() {
    let mut capability =
        FixtureBackend::with_unmount_failure(HostOperationError::CapabilityUnavailable);
    let mut host = FixtureBackend::with_unmount_failure(HostOperationError::DeviceUnavailable);
    let mut device = FixtureBackend::with_eject_dispatch(CommandDispatch::DefinitelyRejected(
        TransportError::CheckCondition(check_condition()),
    ));
    device.keep_target_present();
    let mut inactive = FixtureBackend::with_eject_dispatch(CommandDispatch::NotSent(
        TransportError::InactiveSession,
    ));
    inactive.keep_target_present();
    let mut contradiction = FixtureBackend::with_eject_dispatch(
        CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(check_condition())),
    );
    let mut ambiguous = FixtureBackend::with_eject_dispatch(CommandDispatch::CompletionUnknown(
        TransportError::DeviceRemoved,
    ));
    ambiguous.keep_target_present();
    let mut readback = FixtureBackend::with_readback_failure(HostOperationError::Ambiguous);

    for (expected, backend) in [
        (CliExit::Prerequisite, &mut capability),
        (CliExit::ServiceHost, &mut host),
        (CliExit::Device, &mut device),
        (CliExit::Prerequisite, &mut inactive),
        (CliExit::PartialOrAmbiguous, &mut contradiction),
        (CliExit::PartialOrAmbiguous, &mut ambiguous),
        (CliExit::PartialOrAmbiguous, &mut readback),
    ] {
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let exit = run_with_fixture(
            [OsString::from("--eject"), OsString::from("rdx:fixture")],
            backend,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(exit, expected);
        assert!(output.is_empty());
        assert!(diagnostics.len() <= 256);
    }
}

/// Proves every host readback failure after dispatch is exit 6 in either evidence slot.
#[cfg(feature = "fixtures")]
#[test]
fn post_dispatch_readback_host_errors_are_always_ambiguous() {
    for (error, _) in host_errors_with_pre_dispatch_exits() {
        let mut primary = FixtureBackend::with_readback_failure(error);
        let (primary_exit, primary_output, primary_diagnostics) =
            run_safe_fixture_eject(&mut primary);

        assert_eq!(primary_exit, CliExit::PartialOrAmbiguous, "{error:?}");
        assert!(primary_output.is_empty(), "{error:?}");
        assert!(primary_diagnostics.len() <= 256, "{error:?}");

        let mut cleanup = FixtureBackend::with_eject_dispatch(CommandDispatch::DefinitelyRejected(
            TransportError::CheckCondition(check_condition()),
        ));
        cleanup.fail_next_readback(error);
        let (cleanup_exit, cleanup_output, cleanup_diagnostics) =
            run_safe_fixture_eject(&mut cleanup);

        assert_eq!(cleanup_exit, CliExit::PartialOrAmbiguous, "{error:?}");
        assert!(cleanup_output.is_empty(), "{error:?}");
        assert!(cleanup_diagnostics.len() <= 256, "{error:?}");
    }
}

/// Proves the same host errors retain their typed meaning before eject dispatch.
#[cfg(feature = "fixtures")]
#[test]
fn pre_dispatch_host_errors_keep_their_typed_exit_classes() {
    for (error, expected) in host_errors_with_pre_dispatch_exits() {
        let mut backend = FixtureBackend::with_unmount_failure(error);
        let (exit, output, diagnostics) = run_safe_fixture_eject(&mut backend);

        assert_eq!(exit, expected, "{error:?}");
        assert_eq!(backend.eject_count(), 0, "{error:?}");
        assert_eq!(backend.readback_count(), 0, "{error:?}");
        assert!(output.is_empty(), "{error:?}");
        assert!(diagnostics.len() <= 256, "{error:?}");
    }
}

/// Proves definitive CHECK CONDITION remains exit 4 with exact presence readback.
#[cfg(feature = "fixtures")]
#[test]
fn definitive_terminal_scsi_rejection_remains_device_exit() {
    let mut backend = FixtureBackend::with_eject_dispatch(CommandDispatch::DefinitelyRejected(
        TransportError::CheckCondition(check_condition()),
    ));
    backend.keep_target_present();

    let (exit, output, diagnostics) = run_safe_fixture_eject(&mut backend);

    assert_eq!(exit, CliExit::Device);
    assert!(output.is_empty());
    assert!(diagnostics.len() <= 256);
}

/// Proves missing terminals and backend crashes are completion-ambiguous, never exit 4.
#[cfg(feature = "fixtures")]
#[test]
fn missing_terminal_and_crash_fail_closed_as_ambiguous() {
    let mut missing = FixtureBackend::without_terminal();
    let mut crashed = FixtureBackend::with_crash();

    for backend in [&mut missing, &mut crashed] {
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let exit = run_with_fixture(
            [OsString::from("--eject"), OsString::from("rdx:fixture")],
            backend,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(exit, CliExit::PartialOrAmbiguous);
        assert!(output.is_empty());
    }
}

/// Proves the process-local fixture owner rejects overlapping direct operations.
#[cfg(feature = "fixtures")]
#[test]
fn concurrent_direct_ejects_have_one_exclusive_owner() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let mut first_backend = FixtureBackend::blocking_eject(entered.clone(), release.clone());
    let mut second_backend = FixtureBackend::sharing_ownership(&first_backend);
    let first = thread::spawn(move || {
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let exit = run_with_fixture(
            [OsString::from("--eject"), OsString::from("rdx:fixture")],
            &mut first_backend,
            &mut output,
            &mut diagnostics,
        );
        (exit, first_backend)
    });
    entered.wait();

    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let second_exit = run_with_fixture(
        [OsString::from("--eject"), OsString::from("rdx:fixture")],
        &mut second_backend,
        &mut output,
        &mut diagnostics,
    );
    release.wait();
    let (first_exit, first_backend) = first.join().expect("first fixture operation joins");

    assert_eq!(first_exit, CliExit::Success);
    assert_eq!(first_backend.eject_count(), 1);
    assert_eq!(second_exit, CliExit::Prerequisite);
    assert_eq!(second_backend.scan_count(), 0);
    assert_eq!(second_backend.eject_count(), 0);
}
