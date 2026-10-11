// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_windows_native::{
    ManagerServiceAccessAction, RegistryDaclPrincipal, ServiceDaclPrincipal,
    drive_letter_registry_dacl_contract, parse_manager_service_access_arguments,
    service_dacl_contract,
};

#[test]
fn service_dacl_is_protected_exact_and_manager_cannot_stop_or_reconfigure() {
    let contract = service_dacl_contract();

    assert_eq!(contract.service_name, "OpenRDXHardwareService");
    assert!(contract.protected);
    assert_eq!(contract.entries.len(), 4);
    assert_eq!(
        contract.entries[0].principal,
        ServiceDaclPrincipal::LocalSystem
    );
    assert_eq!(
        contract.entries[1].principal,
        ServiceDaclPrincipal::Administrators
    );
    assert_eq!(
        contract.entries[2].principal,
        ServiceDaclPrincipal::LocalService
    );
    assert_eq!(
        contract.entries[3].principal,
        ServiceDaclPrincipal::ManagerUser
    );
    assert_eq!(contract.entries[3].access_mask, 0x0000_0015);
    assert_eq!(contract.entries[3].access_mask & 0x0001_0002, 0);
}

#[test]
fn drive_letter_registry_acl_is_protected_owned_and_least_privilege() {
    let contract = drive_letter_registry_dacl_contract();

    assert_eq!(
        contract.key,
        r"HKEY_LOCAL_MACHINE\SOFTWARE\OpenRDXManager\DriveLetters"
    );
    assert!(contract.protected);
    assert_eq!(contract.owner, RegistryDaclPrincipal::Administrators);
    assert_eq!(contract.group, RegistryDaclPrincipal::LocalSystem);
    assert_eq!(contract.entries.len(), 4);
    assert_eq!(
        contract.entries[0].principal,
        RegistryDaclPrincipal::LocalSystem
    );
    assert_eq!(
        contract.entries[1].principal,
        RegistryDaclPrincipal::Administrators
    );
    assert_eq!(
        contract.entries[2].principal,
        RegistryDaclPrincipal::LocalService
    );
    assert_eq!(contract.entries[2].access_mask, 0x0002_000f);
    assert_eq!(contract.entries[2].access_mask & 0x0001_0000, 0);
    assert_eq!(contract.entries[2].access_mask & 0x000c_0000, 0);
    assert!(!contract.entries[2].inherit_only);
    assert_eq!(
        contract.entries[3].principal,
        RegistryDaclPrincipal::LocalService
    );
    assert_eq!(contract.entries[3].access_mask, 0x0003_000f);
    assert_eq!(contract.entries[3].access_mask & 0x000c_0000, 0);
    assert!(contract.entries[3].container_inherit);
    assert!(contract.entries[3].inherit_only);
}

#[test]
fn elevated_installer_interface_accepts_only_action_and_manager_process_id() {
    for (action, expected) in [
        ("provision", ManagerServiceAccessAction::Provision),
        ("verify", ManagerServiceAccessAction::Verify),
        ("remove", ManagerServiceAccessAction::Remove),
    ] {
        let parsed = parse_manager_service_access_arguments(&[
            "--action",
            action,
            "--manager-process-id",
            "4242",
        ])
        .unwrap();
        assert_eq!(parsed.action(), expected);
        assert_eq!(parsed.manager_process_id(), 4242);
    }

    for rejected in [
        vec!["--action", "provision", "--manager-sid", "S-1-5-21-1"],
        vec!["--action", "provision", "--service", "attacker"],
        vec!["--action", "provision", "--path", r"C:\\attacker.exe"],
        vec!["--action", "provision", "--manager-process-id", "0"],
        vec![
            "--action",
            "provision",
            "--manager-process-id",
            "4242",
            "extra",
        ],
    ] {
        assert!(parse_manager_service_access_arguments(&rejected).is_err());
    }
}
