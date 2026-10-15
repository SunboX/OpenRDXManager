// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::{cell::Cell, ffi::CString};

/// Private metadata fixture cannot authenticate signed code, a runtime or a production factory.
fn inventory() -> RuntimeInventory {
    RuntimeInventory {
        schema_version: 1,
        platform: "macos".into(),
        manager_cd_hash: "a".repeat(40),
        helper_cd_hash: "b".repeat(40),
        links: Vec::new(),
        files: vec![RuntimeFile {
            path: local_trust::HELPER_INVENTORY_PATH.into(),
            size: 4,
            sha256: "d".repeat(64),
        }],
    }
}

/// Verifier injection exists only in this cfg(test) module, not as a production override.
struct FixtureVerifier<'a> {
    calls: &'a Cell<u32>,
    result: Result<(), NativeError>,
}
impl StandaloneVerifier for FixtureVerifier<'_> {
    /// Records only the exact bundled entry and models unavailable standalone bytes without OS access.
    fn verify(&self, helper: &RuntimeFile) -> Result<(), NativeError> {
        assert_eq!(helper.path, local_trust::HELPER_INVENTORY_PATH);
        assert_eq!(helper.size, 4);
        assert_eq!(helper.sha256, "d".repeat(64));
        self.calls.set(self.calls.get() + 1);
        self.result
    }
}

/// Signed-only inventory must never consult a missing or rejected local standalone helper.
#[test]
fn signed_helper_inventory_has_no_standalone_dependency() {
    let calls = Cell::new(0);
    let verifier = FixtureVerifier {
        calls: &calls,
        result: Err(NativeError::AccessDenied),
    };
    assert_eq!(
        HelperLocation::SignedBundled.verify_inventory_with(&inventory(), &verifier),
        Ok(())
    );
    assert_eq!(calls.get(), 0);
}

/// Locally enrolled generations must still freshly verify the exact standalone bytes.
#[test]
fn local_helper_inventory_requires_standalone_verification_and_entry_in_both_modes() {
    for result in [Ok(()), Err(NativeError::AccessDenied)] {
        let calls = Cell::new(0);
        let verifier = FixtureVerifier {
            calls: &calls,
            result,
        };
        assert_eq!(
            HelperLocation::LocalStandalone.verify_inventory_with(&inventory(), &verifier),
            result
        );
        assert_eq!(calls.get(), 1);
    }
    let mut missing = inventory();
    missing.files.clear();
    for mode in [
        HelperLocation::LocalStandalone,
        HelperLocation::SignedBundled,
    ] {
        let calls = Cell::new(0);
        let verifier = FixtureVerifier {
            calls: &calls,
            result: Ok(()),
        };
        assert_eq!(
            mode.verify_inventory_with(&missing, &verifier),
            Err(NativeError::AccessDenied)
        );
        assert_eq!(calls.get(), 0);
    }
}

/// The actual production-consumed executable predicate is exact and generation-specific.
#[test]
fn helper_current_executable_must_match_each_retained_mode_without_fallback() {
    let local = HelperLocation::LocalStandalone;
    let signed = HelperLocation::SignedBundled;
    assert_eq!(local.verify_current_executable(local.path()), Ok(()));
    assert_eq!(signed.verify_current_executable(signed.path()), Ok(()));
    assert_eq!(
        local.verify_current_executable(signed.path()),
        Err(NativeError::AccessDenied)
    );
    assert_eq!(
        signed.verify_current_executable(local.path()),
        Err(NativeError::AccessDenied)
    );
    assert_eq!(
        signed.verify_current_executable(Path::new("/tmp/openrdx-hardware")),
        Err(NativeError::AccessDenied)
    );
}

/// Only the already accepted exact canonical signed-team or local requirement selects location.
#[test]
fn helper_location_requires_pinned_canonical_manager_requirement() {
    let local = CString::new(crate::local_manager_requirement(&"a".repeat(40)).unwrap()).unwrap();
    let signed=CString::new("identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"TESTTEAM01\"").unwrap();
    assert_eq!(
        HelperLocation::from_requirement(&local),
        Ok(HelperLocation::LocalStandalone)
    );
    assert_eq!(
        HelperLocation::from_requirement(&signed),
        Ok(HelperLocation::SignedBundled)
    );
    for req in [
        "",
        "identifier \"com.openrdx.manager\"",
        "identifier \"com.openrdx.manager\" and cdhash H\"bad\"",
        "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"testteam01\"",
    ] {
        assert_eq!(
            HelperLocation::from_requirement(&CString::new(req).unwrap()),
            Err(NativeError::InvalidRequest)
        );
    }
}
