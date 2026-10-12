// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_windows_native::{
    LocalInstallAction, RuntimeAce, RuntimeAclEvidence, parse_local_install_arguments,
    validate_runtime_acl,
};

#[test]
fn installer_accepts_only_fixed_actions_and_live_pid() {
    assert_eq!(
        parse_local_install_arguments(&["--action", "verify"])
            .unwrap()
            .action(),
        LocalInstallAction::Verify
    );
    assert!(parse_local_install_arguments(&["--action", "install"]).is_err());
    assert!(
        parse_local_install_arguments(&["--action", "install", "--manager-process-id", "0"])
            .is_err()
    );
    assert!(
        parse_local_install_arguments(&[
            "--action",
            "install",
            "--manager-process-id",
            "123",
            "--path",
            "x"
        ])
        .is_err()
    );
    assert!(parse_local_install_arguments(&["--action", "enroll-arbitrary-path"]).is_err());
    assert_eq!(
        parse_local_install_arguments(&["--action", "repair", "--manager-process-id", "123"])
            .unwrap()
            .manager_process_id(),
        Some(123)
    );
}

fn protected() -> RuntimeAclEvidence {
    RuntimeAclEvidence {
        owner: "S-1-5-32-544".into(),
        protected: true,
        reparse: false,
        directory: false,
        links: 1,
        entries: vec![
            RuntimeAce {
                sid: "S-1-5-18".into(),
                mask: 0x001f01ff,
                flags: 0,
                allowed: true,
            },
            RuntimeAce {
                sid: "S-1-5-32-544".into(),
                mask: 0x001f01ff,
                flags: 0,
                allowed: true,
            },
            RuntimeAce {
                sid: "S-1-5-19".into(),
                mask: 0x001200a9,
                flags: 0,
                allowed: true,
            },
            RuntimeAce {
                sid: "S-1-5-32-545".into(),
                mask: 0x001200a9,
                flags: 0,
                allowed: true,
            },
        ],
    }
}

#[test]
fn complete_policy_rejects_writable_foreign_and_reparse_runtime() {
    assert!(validate_runtime_acl(&protected()).is_ok());
    let mut policy = protected();
    policy.owner = "S-1-5-21-1-2-3-1000".into();
    assert!(validate_runtime_acl(&policy).is_err());
    let mut policy = protected();
    policy.entries[3].mask |= 2;
    assert!(validate_runtime_acl(&policy).is_err());
    let mut policy = protected();
    policy.reparse = true;
    assert!(validate_runtime_acl(&policy).is_err());
    let mut policy = protected();
    policy.links = 2;
    assert!(validate_runtime_acl(&policy).is_err());
    let mut policy = protected();
    policy.protected = false;
    assert!(validate_runtime_acl(&policy).is_err());
    let mut policy = protected();
    policy.entries.push(RuntimeAce {
        sid: "S-1-1-0".into(),
        mask: 1,
        flags: 0,
        allowed: true,
    });
    assert!(validate_runtime_acl(&policy).is_err());
}

#[cfg(not(windows))]
#[test]
fn native_client_boundary_never_authorizes_foreign_hosts() {
    assert!(rdx_windows_native::openrdx_local_trust_open().is_null());
}

#[test]
fn raw_permissions_require_complete_positive_rdx_identity_pair() {
    let mut standard = vec![0; 43];
    standard[4] = 38;
    standard[8..16].copy_from_slice(b"TANDBERG");
    standard[16..32].copy_from_slice(b"RDX             ");
    standard[37..40].copy_from_slice(b"RDX");
    let mut vpd = vec![0; 42];
    vpd[1] = 0x83;
    vpd[3] = 38;
    vpd[8..16].copy_from_slice(b"TANDBERG");
    vpd[16..32].copy_from_slice(b"RDX             ");
    vpd[32..42].copy_from_slice(b"1234567890");
    assert_eq!(
        rdx_windows_native::rdx_permission_identity(&standard, &vpd).unwrap(),
        "1234567890"
    );
    let mut unknown = standard.clone();
    unknown[37] = b'X';
    assert!(rdx_windows_native::rdx_permission_identity(&unknown, &vpd).is_err());
    let mut mismatch = vpd.clone();
    mismatch[8] = b'H';
    assert!(rdx_windows_native::rdx_permission_identity(&standard, &mismatch).is_err());
    assert!(rdx_windows_native::rdx_permission_identity(&standard[..36], &vpd).is_err());
    standard[36] = 0xff;
    assert!(rdx_windows_native::rdx_permission_identity(&standard, &vpd).is_err());
}

#[test]
fn uninstall_restore_requires_current_policy_and_exact_instance_generation() {
    assert!(rdx_windows_native::safe_device_acl_restore(
        "instance-A",
        "serial-A",
        "our-descriptor",
        "instance-A",
        "serial-A",
        "our-descriptor"
    ));
    assert!(!rdx_windows_native::safe_device_acl_restore(
        "instance-A",
        "serial-A",
        "our-descriptor",
        "instance-A",
        "serial-A",
        "admin-changed-descriptor"
    ));
    assert!(!rdx_windows_native::safe_device_acl_restore(
        "instance-A",
        "serial-A",
        "our-descriptor",
        "instance-B",
        "serial-A",
        "our-descriptor"
    ));
    assert!(!rdx_windows_native::safe_device_acl_restore(
        "instance-A",
        "serial-A",
        "our-descriptor",
        "instance-A",
        "serial-B",
        "our-descriptor"
    ));
}

#[test]
fn preupgrade_preparation_has_no_identity_or_path_input() {
    assert_eq!(
        parse_local_install_arguments(&["--action", "prepare"])
            .unwrap()
            .action(),
        LocalInstallAction::Prepare
    );
    assert!(
        parse_local_install_arguments(&["--action", "prepare", "--manager-process-id", "123"])
            .is_err()
    );
}

#[test]
fn interrupted_device_setup_only_repairs_exact_journal_state() {
    assert!(rdx_windows_native::safe_device_acl_repair(
        "i",
        "s",
        "installed",
        None,
        "i",
        "s",
        None
    ));
    assert!(rdx_windows_native::safe_device_acl_repair(
        "i",
        "s",
        "installed",
        Some("prior"),
        "i",
        "s",
        Some("prior")
    ));
    assert!(rdx_windows_native::safe_device_acl_repair(
        "i",
        "s",
        "installed",
        Some("prior"),
        "i",
        "s",
        Some("installed")
    ));
    assert!(!rdx_windows_native::safe_device_acl_repair(
        "i",
        "s",
        "installed",
        Some("prior"),
        "i",
        "s",
        Some("administrator-changed")
    ));
    assert!(!rdx_windows_native::safe_device_acl_repair(
        "i",
        "s",
        "installed",
        None,
        "i",
        "new-s",
        None
    ));
}

#[test]
fn interrupted_extraction_accepts_only_exact_privileged_inherited_policy() {
    let mut policy = protected();
    policy.protected = false;
    for ace in &mut policy.entries {
        ace.flags = 16;
    }
    assert!(rdx_windows_native::validate_interrupted_runtime_acl(&policy).is_ok());
    assert!(validate_runtime_acl(&policy).is_err());
    policy.entries[3].mask |= 2;
    assert!(rdx_windows_native::validate_interrupted_runtime_acl(&policy).is_err());
    policy.entries[3].mask &= !2;
    policy.owner = "S-1-5-21-1-2-3-1000".into();
    assert!(rdx_windows_native::validate_interrupted_runtime_acl(&policy).is_err());
}
