// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use rdx_local_trust::{RuntimeFile, RuntimeInventory, RuntimeLink};

/// Canonical comparison includes every file/link/code pin and ignores enumeration order only.
#[test]
fn runtime_generation_full_inventory_changes_are_not_uid_equivalent() {
    let mut inventory = inventory();
    let original = RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory);
    inventory.files.reverse();
    assert!(
        original == RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory)
    );
    inventory.files[0].sha256 = "f".repeat(64);
    assert!(
        original != RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory)
    );
    inventory = self::inventory();
    inventory.files[0].size += 1;
    assert!(
        original != RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory)
    );
    inventory = self::inventory();
    inventory.links[0].target = "Versions/B".into();
    assert!(
        original != RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory)
    );
    inventory = self::inventory();
    inventory.helper_cd_hash = "e".repeat(40);
    assert!(
        original != RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory)
    );
    inventory = self::inventory();
    inventory.manager_cd_hash = "d".repeat(40);
    assert!(
        original != RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory)
    );
    assert!(
        original
            != RuntimeGeneration::from_inventory(HelperLocation::SignedBundled, &self::inventory())
    );
}

/// Metadata fixtures cannot be passed to public factory constructors.
fn inventory() -> RuntimeInventory {
    RuntimeInventory {
        schema_version: 1,
        platform: "macos".into(),
        manager_cd_hash: "a".repeat(40),
        helper_cd_hash: "b".repeat(40),
        files: vec![
            RuntimeFile {
                path: "Contents/MacOS/OpenRDXManager".into(),
                size: 3,
                sha256: "c".repeat(64),
            },
            RuntimeFile {
                path: "Contents/Library/LaunchServices/openrdx-hardware".into(),
                size: 4,
                sha256: "d".repeat(64),
            },
        ],
        links: vec![RuntimeLink {
            path: "Contents/Frameworks/A.framework/Versions/Current".into(),
            target: "A".into(),
        }],
    }
}

/// Fresh protected snapshots cannot switch the original helper mode even if all inventory bytes match.
#[test]
fn runtime_generation_revalidation_refuses_changed_helper_location() {
    let inventory = inventory();
    let local = RuntimeGeneration::from_inventory(HelperLocation::LocalStandalone, &inventory);
    let signed = RuntimeGeneration::from_inventory(HelperLocation::SignedBundled, &inventory);
    assert_eq!(local.compare_current_generation(&local), Ok(()));
    assert_eq!(signed.compare_current_generation(&signed), Ok(()));
    assert_eq!(
        local.compare_current_generation(&signed),
        Err(NativeError::AccessDenied)
    );
    assert_eq!(
        signed.compare_current_generation(&local),
        Err(NativeError::AccessDenied)
    );
    assert_eq!(local.helper_location(), HelperLocation::LocalStandalone);
    assert_eq!(signed.helper_location(), HelperLocation::SignedBundled);
}
