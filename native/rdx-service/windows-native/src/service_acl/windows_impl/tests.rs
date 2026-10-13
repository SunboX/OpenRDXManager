// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Causal service-security fixtures; never production service or user authentication.
use super::*;
use windows::Win32::System::Services::{CreateServiceW, DeleteService, SC_MANAGER_CREATE_SERVICE};
use windows::Win32::System::Threading::GetCurrentProcess;

struct FixtureService(OwnedService);
impl Drop for FixtureService {
    /// Deletes only the exact successful CreateService handle owned by this fixture.
    fn drop(&mut self) {
        unsafe { DeleteService(self.0.0) }.unwrap();
    }
}
/// Creates one never-started private service with a harmless test image and creator-only ownership.
fn fixture_service() -> FixtureService {
    let manager =
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CREATE_SERVICE) }
            .map(OwnedService)
            .unwrap();
    let name = wide_null(OsStr::new(&format!(
        "OpenRDXPrivateDaclFixture{}",
        std::process::id()
    )));
    let binary = wide_null(std::env::current_exe().unwrap().as_os_str());
    let account = wide_null(OsStr::new("NT AUTHORITY\\LocalService"));
    FixtureService(OwnedService(
        unsafe {
            CreateServiceW(
                manager.0,
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                SERVICE_QUERY_CONFIG | READ_CONTROL.0 | WRITE_DAC.0 | 0x10000,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(binary.as_ptr()),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR(account.as_ptr()),
                PCWSTR::null(),
            )
        }
        .unwrap(),
    ))
}
/// Requires native readback of the actual canonical DACL, without starting the fixture.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_service_setter_retains_exact_protected_dacl() {
    let fixture = fixture_service();
    let mut raw = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }.unwrap();
    let creator = token_user_sid(&OwnedHandle(raw)).unwrap();
    // The creator SID is an opaque setter fixture, never a Manager authentication proof.
    let baseline = query_service_configuration(&fixture.0).unwrap();
    set_exact_dacl(&fixture.0, &creator, true).unwrap();
    let storage = read_service_security(&fixture.0).unwrap();
    let mut control = 0u16;
    let mut revision = 0u32;
    unsafe {
        GetSecurityDescriptorControl(
            PSECURITY_DESCRIPTOR(storage.as_ptr().cast_mut().cast()),
            &mut control,
            &mut revision,
        )
    }
    .unwrap();
    eprintln!(
        "fixture-dacl-protected={} revision={revision}",
        control & SE_DACL_PROTECTED.0 != 0
    );
    assert!(
        exact_dacl_matches(&fixture.0, &creator, true).unwrap(),
        "setter must retain canonical protected descriptor"
    );
    set_exact_dacl(&fixture.0, &creator, false).unwrap();
    assert!(exact_dacl_matches(&fixture.0, &creator, false).unwrap());
    assert!(!exact_dacl_matches(&fixture.0, &creator, true).unwrap());
    assert_eq!(query_service_configuration(&fixture.0).unwrap(), baseline);
}
