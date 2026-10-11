// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(not(target_os = "linux"))]
use rdx_linux_native::{NativeError, enumerate_scsi_generic_candidates, probe_readiness};
use rdx_linux_native::{ScsiOperation, sg_open_requirements};

/// Non-Linux builds expose only truthful unavailable behavior.
#[cfg(not(target_os = "linux"))]
#[test]
fn native_entry_points_are_target_gated_off_linux() {
    let readiness = probe_readiness();

    assert!(!readiness.sysfs_available());
    assert!(!readiness.udev_rules_installed());
    assert!(!readiness.current_ipc_group_member());
    assert_eq!(
        enumerate_scsi_generic_candidates(),
        Err(NativeError::UnsupportedPlatform),
    );
}

/// Semantic operations redact their CDB, timeout, payload, and selectors.
#[test]
fn semantic_operation_debug_is_fully_redacted() {
    let operation = ScsiOperation::firmware_chunk(0x012345, vec![0xA5; 32])
        .expect("bounded semantic operation");

    assert_eq!(format!("{operation:?}"), "ScsiOperation(<private>)");
}

/// The public pointer-free policy names the exact flags translated by the
/// Linux-only open boundary, including exclusive ownership.
#[test]
fn sg_open_policy_is_exact_and_exclusive() {
    let policy = sg_open_requirements();

    assert!(policy.read_write());
    assert!(policy.exclusive());
    assert!(policy.nonblocking());
    assert!(policy.close_on_exec());
    assert!(policy.no_follow());
}

/// Static macOS review proves the native boundary declares every unsafe block.
#[test]
fn linux_native_boundary_has_audited_unsafe_blocks_and_safe_open_flags() {
    let source = include_str!("../src/native.rs");
    let unsafe_blocks = source.matches("unsafe {").count();
    let safety_comments = source.matches("// SAFETY:").count();

    assert!(unsafe_blocks > 0);
    assert_eq!(unsafe_blocks, safety_comments);
    assert!(source.contains("SG_IO"));
    assert!(!source.contains("service_installed = false"));
    assert!(!source.contains("OPENRDX_SERVICE_READY"));
    assert!(!source.contains("Command::new"));
}

/// Fixed formatting tools can see only the inherited descriptor after the
/// child makes its mount namespace private and masks the host `/dev` tree.
#[test]
fn formatter_source_contract_is_fd_only_and_namespace_isolated() {
    let source = include_str!("../src/native/formatting.rs");

    assert!(source.contains("const CHILD_BLOCK_FD: libc::c_int = 9;"));
    assert!(source.contains("const CHILD_BLOCK_PATH: &str = \"/proc/self/fd/9\";"));
    assert!(source.contains("libc::unshare(libc::CLONE_NEWNS)"));
    assert!(source.contains("libc::MS_REC | libc::MS_PRIVATE"));
    assert!(source.contains("c\"openrdx-sandbox\""));
    assert!(source.contains("c\"/dev\""));
    assert!(source.contains("c\"tmpfs\""));
    assert!(source.contains("libc::PR_SET_NO_NEW_PRIVS"));
    assert!(!source.contains("sh -c"));
    assert!(!source.contains("/dev/sd"));
}

/// Host unmount uses an uncached root-owned daemon object and kernel readback,
/// with no pathname unmount or forced/lazy fallback.
#[test]
fn unmount_source_contract_is_exact_normal_host_request() {
    let source = concat!(
        include_str!("../src/native/unmount.rs"),
        include_str!("../src/native/udisks.rs"),
        include_str!("../src/host_unmount.rs")
    );

    assert!(source.contains("GetConnectionUnixUser"));
    assert!(source.contains("CacheProperties::No"));
    assert!(source.contains("DeviceNumber"));
    assert!(source.contains("MountPoints"));
    assert!(source.contains("Value::Bool(false)"));
    assert!(source.contains("release_mount_handles"));
    assert!(source.contains("verify_unmounted"));
    assert!(!source.contains("libc::umount2"));
    assert!(!source.contains("MNT_DETACH"));
    assert!(!source.contains("--force"));
}

/// The packaged Linux acceptance notes keep native and physical proof separate.
#[test]
fn linux_verification_contract_names_native_ci_without_claiming_hardware() {
    let readme = include_str!("../../resources/linux/README.md");

    assert!(readme.contains("ubuntu-latest"));
    assert!(readme.contains("cargo clippy"));
    assert!(readme.contains("cargo test"));
    assert!(readme.contains("No physical RDX hardware verification"));
    assert!(readme.contains("70-openrdx.rules"));
    assert!(readme.contains("org.openrdx.hardware.policy"));
}

/// Compile-fail contracts keep descriptors, paths, recipes, and raw CDBs private.
#[test]
fn unsafe_native_surfaces_are_not_public() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
