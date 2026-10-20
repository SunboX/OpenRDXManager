// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed SCM registration. Updates refuse live hardware service sessions.
use super::diagnostics::{InstallStage as Stage, diagnostic};
use super::{LocalInstallAction, LocalInstallCommand};
use crate::local_trust::{
    LOCAL_RUNTIME_ROOT, LOCAL_SERVICE_BINARY, commit_enrollment, prepare_runtime,
    remove_enrollment, verify_owned_runtime_lease, verify_runtime_lease,
};
use crate::{NativeError, apply_manager_service_access, parse_manager_service_access_arguments};
use std::mem::{size_of, size_of_val};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::Services::*;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

const SERVICE_NAME: &str = "OpenRDXHardwareService";
const DISPLAY_NAME: &str = "OpenRDX Hardware Service";
// Both SCM query APIs document an 8 KiB buffer limit, measured in bytes.
// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw
// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceobjectsecurity
const MAX_SERVICE_QUERY_BYTES: usize = 8_192;
/// Allocates aligned storage for configuration and owner-security SCM queries.
fn service_query_storage() -> Vec<usize> {
    vec![0usize; MAX_SERVICE_QUERY_BYTES / size_of::<usize>()]
}
/// Terminates a Rust string for a synchronous Win32 call.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
struct Service(SC_HANDLE);
impl Drop for Service {
    /// Releases exactly one owned SCM handle.
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}
/// Obtains the elevated installer's actual token owner for initial NSIS-created files.
fn installer_sid() -> Result<String, NativeError> {
    let mut raw = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }
        .map_err(|_| NativeError::AccessDenied)?;
    let mut storage = vec![0usize; 512];
    let mut returned = 0;
    let result = unsafe {
        GetTokenInformation(
            raw,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            (storage.len() * size_of::<usize>()) as u32,
            &mut returned,
        )
    };
    let _ = unsafe { CloseHandle(raw) };
    result.map_err(|_| NativeError::AccessDenied)?;
    if returned as usize > storage.len() * size_of::<usize>()
        || (returned as usize) < size_of::<TOKEN_USER>()
    {
        return Err(NativeError::AccessDenied);
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }
        .map_err(|_| NativeError::AccessDenied)?;
    let converted = unsafe { text.to_string() };
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    converted.map_err(|_| NativeError::AccessDenied)
}
/// Proves exact configuration using bounded pointers before ownership-sensitive changes.
fn configuration(service: &Service) -> Result<(), NativeError> {
    let mut storage = service_query_storage();
    let mut needed = 0;
    let raw = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    unsafe {
        QueryServiceConfigW(
            service.0,
            Some(raw),
            (storage.len() * size_of::<usize>()) as u32,
            &mut needed,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let cfg = unsafe { &*raw };
    let string = |pointer: PWSTR| -> Result<String, NativeError> {
        let start = storage.as_ptr() as usize;
        let end = start + storage.len() * size_of::<usize>();
        let address = pointer.0 as usize;
        if address < start + size_of::<QUERY_SERVICE_CONFIGW>()
            || address >= end
            || address % 2 != 0
        {
            return Err(NativeError::AccessDenied);
        }
        let units = unsafe { std::slice::from_raw_parts(pointer.0, (end - address) / 2) };
        let len = units
            .iter()
            .position(|v| *v == 0)
            .ok_or(NativeError::AccessDenied)?;
        String::from_utf16(&units[..len]).map_err(|_| NativeError::AccessDenied)
    };
    let exact =
        format!("\"{LOCAL_SERVICE_BINARY}\" --service-mode named-pipe --protocol-version 1");
    if cfg.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || cfg.dwStartType != SERVICE_DEMAND_START
        || cfg.dwErrorControl != SERVICE_ERROR_NORMAL
        || string(cfg.lpBinaryPathName)? != exact
        || string(cfg.lpServiceStartName)? != "NT AUTHORITY\\LocalService"
        || string(cfg.lpDisplayName)? != DISPLAY_NAME
        || !string(cfg.lpLoadOrderGroup)?.is_empty()
        || !string(cfg.lpDependencies)?.is_empty()
    {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}
/// Refuses replacement/removal until the service has naturally drained and stopped.
fn require_stopped(service: &Service) -> Result<(), NativeError> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>(),
        )
    };
    unsafe { QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed) }
        .map_err(|_| NativeError::AccessDenied)?;
    if status.dwCurrentState != SERVICE_STOPPED {
        return Err(NativeError::Busy);
    }
    Ok(())
}
/// Runs installer operations with fixed roots and elevated authority, never IPC policy.
pub(super) fn apply(command: LocalInstallCommand) -> Result<(), NativeError> {
    if !crate::current_process_is_elevated() {
        return Err(NativeError::AccessDenied);
    }
    let current = std::env::current_exe().map_err(|_| NativeError::AccessDenied)?;
    let expected = std::path::Path::new(LOCAL_RUNTIME_ROOT)
        .join("resources/native/windows/openrdx-local-install.exe");
    if current != expected
        && !(matches!(
            command.action(),
            LocalInstallAction::Prepare | LocalInstallAction::Remove
        ) && current.file_name() == Some(std::ffi::OsStr::new("openrdx-local-install.exe")))
    {
        return Err(NativeError::AccessDenied);
    }
    let manager = Service(
        unsafe {
            OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?,
    );
    let name = wide(SERVICE_NAME);
    let existing = unsafe {
        OpenServiceW(
            manager.0,
            PCWSTR(name.as_ptr()),
            SERVICE_QUERY_CONFIG
                | SERVICE_QUERY_STATUS
                | SERVICE_CHANGE_CONFIG
                | SERVICE_STOP
                | 0x00010000
                | 0x00020000
                | 0x00040000
                | 0x00080000,
        )
    };
    let newly_created = existing.is_err();
    let service = match existing {
        Ok(handle) => {
            let service = Service(handle);
            diagnostic(Stage::ServiceConfiguration, configuration(&service))?;
            if !matches!(
                command.action(),
                LocalInstallAction::Verify | LocalInstallAction::Prepare
            ) {
                require_stopped(&service)?;
            }
            service
        }
        Err(error)
            if error.code().0 as u32 & 0xffff == 1060
                && matches!(
                    command.action(),
                    LocalInstallAction::Install | LocalInstallAction::Repair
                ) =>
        {
            let binary = wide(&format!(
                "\"{LOCAL_SERVICE_BINARY}\" --service-mode named-pipe --protocol-version 1"
            ));
            let account = wide("NT AUTHORITY\\LocalService");
            let display = wide(DISPLAY_NAME);
            Service(
                unsafe {
                    CreateServiceW(
                        manager.0,
                        PCWSTR(name.as_ptr()),
                        PCWSTR(display.as_ptr()),
                        SERVICE_QUERY_CONFIG
                            | SERVICE_QUERY_STATUS
                            | SERVICE_CHANGE_CONFIG
                            | 0x00010000
                            | 0x00020000
                            | 0x00040000
                            | 0x00080000,
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
                .map_err(|_| NativeError::AccessDenied)?,
            )
        }
        Err(error)
            if error.code().0 as u32 & 0xffff == 1060
                && matches!(
                    command.action(),
                    LocalInstallAction::Remove | LocalInstallAction::Prepare
                ) =>
        {
            if command.action() == LocalInstallAction::Prepare
                && !std::path::Path::new(crate::local_trust::LOCAL_ENROLLMENT_ROOT)
                    .join("history.json")
                    .exists()
            {
                crate::local_trust::bootstrap::prepare_first_install()?;
            } else if std::path::Path::new(LOCAL_RUNTIME_ROOT).exists() {
                let _lease = verify_owned_runtime_lease()?;
                drop(_lease);
                remove_enrollment()?;
            } else if command.action() == LocalInstallAction::Prepare {
                crate::local_trust::bootstrap::prepare_first_install()?;
            } else {
                crate::local_trust::windows::verify_fresh_install_root()?;
            }
            return Ok(());
        }
        Err(_) => return Err(NativeError::AccessDenied),
    };
    diagnostic(Stage::ServiceConfiguration, configuration(&service))?;
    diagnostic(
        Stage::ServiceOwner,
        verify_service_owner(&service, newly_created),
    )?;
    if !newly_created
        && matches!(
            command.action(),
            LocalInstallAction::Install | LocalInstallAction::Repair
        )
    {
        let _history = verify_owned_runtime_lease()?;
    }
    match command.action() {
        LocalInstallAction::Prepare => diagnostic(Stage::ServiceQuiescence, quiesce(&service))?,
        LocalInstallAction::Install | LocalInstallAction::Repair => {
            revoke_admission(&service)?;
            remove_enrollment()?;
            let result = (|| {
                let sid = SERVICE_SID_INFO {
                    dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
                };
                unsafe {
                    ChangeServiceConfig2W(
                        service.0,
                        SERVICE_CONFIG_SERVICE_SID_INFO,
                        Some((&sid as *const SERVICE_SID_INFO).cast()),
                    )
                }
                .map_err(|_| NativeError::AccessDenied)?;
                let administrator_sid = installer_sid()?;
                let candidate =
                    diagnostic(Stage::InstalledRuntime, prepare_runtime(&administrator_sid))?;
                // Provision the private leaf while elevated, after parent policy is
                // final. Retain its ancestry through admission and enrollment;
                // existing storage is verified without rewriting backup records.
                let _manufacturing_store = diagnostic(
                    Stage::ManufacturingStorage,
                    crate::manufacturing_storage::ManufacturingStore::open(),
                )?;
                let pid = command
                    .manager_process_id()
                    .ok_or(NativeError::InvalidRequest)?
                    .to_string();
                for action in ["provision", "verify"] {
                    diagnostic(
                        Stage::ManagerAccess,
                        crate::service_acl::apply_installer_manager_service_access(
                            parse_manager_service_access_arguments(&[
                                "--action",
                                action,
                                "--manager-process-id",
                                &pid,
                            ])?,
                        ),
                    )?;
                }
                diagnostic(
                    Stage::DeviceAccess,
                    crate::native::device_access::provision(&administrator_sid),
                )?;
                diagnostic(Stage::ServiceSid, verify_service_sid(&service))?;
                diagnostic(
                    Stage::CommitEnrollment,
                    commit_enrollment(&candidate, &administrator_sid),
                )?;
                let _lease = diagnostic(Stage::VerifyEnrollment, verify_runtime_lease())?;
                Ok(())
            })();
            if let Err(error) = result {
                // Revoke start before deleting enrollment so no partially prepared
                // generation is admitted even if cleanup itself cannot complete.
                revoke_admission(&service)?;
                remove_enrollment()?;
                return Err(error);
            }
        }
        LocalInstallAction::Verify => {
            diagnostic(Stage::ServiceSid, verify_service_sid(&service))?;
            diagnostic(Stage::DeviceAccess, verify_volume_maintenance_right())?;
            let _lease = diagnostic(Stage::VerifyEnrollment, verify_runtime_lease())?;
            if let Some(pid) = command.manager_process_id() {
                let pid = pid.to_string();
                apply_manager_service_access(parse_manager_service_access_arguments(&[
                    "--action",
                    "verify",
                    "--manager-process-id",
                    &pid,
                ])?)?;
            }
        }
        LocalInstallAction::Remove => {
            let _lease = verify_owned_runtime_lease()?;
            require_stopped(&service)?;
            diagnostic(Stage::DeviceAccess, crate::native::device_access::restore())?;
            unsafe { DeleteService(service.0) }.map_err(|_| NativeError::AccessDenied)?;
            drop(_lease);
            remove_enrollment()?;
        }
    }
    Ok(())
}

/// Verifies the installer enrolled the fixed service-specific filesystem privilege.
fn verify_volume_maintenance_right() -> Result<(), NativeError> {
    if crate::volume_privilege::has_service_right()? {
        Ok(())
    } else {
        Err(NativeError::AccessDenied)
    }
}

/// Closes admission only after acquiring the service's same protected operation lock.
/// Active hardware sessions are refused without sending STOP or replacing any file.
fn quiesce(service: &Service) -> Result<(), NativeError> {
    let trust = verify_owned_runtime_lease()?;
    // Remove ordinary-user START while the same global device lock prevents a
    // retained connection from admitting new hardware work during shutdown.
    let _exclusive = crate::ownership::try_acquire_installer_quiescence()?;
    revoke_admission(service)?;
    if require_stopped(service).is_err() {
        if _exclusive.is_none() {
            return Err(NativeError::AccessDenied);
        }
        let mut status = SERVICE_STATUS::default();
        unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) }
            .map_err(|_| NativeError::AccessDenied)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while require_stopped(service).is_err() {
            if std::time::Instant::now() >= deadline {
                return Err(NativeError::Busy);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    drop(trust);
    remove_enrollment()
}
/// Installs the fixed protected base DACL, revoking every ordinary-user START grant.
fn revoke_admission(service: &Service) -> Result<(), NativeError> {
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    // Keep the daemon's independent read-only identity checks available while
    // ordinary-user START is revoked during installation or repair.
    let text = wide("D:P(A;;0x000f01ff;;;SY)(A;;0x000f01ff;;;BA)(A;;0x00000005;;;LS)");
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let result = unsafe {
        SetServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        )
    };
    let _ = unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    result.map_err(|_| NativeError::AccessDenied)
}

/// Requires the service-specific SID policy before verifying the installed service.
fn verify_service_sid(service: &Service) -> Result<(), NativeError> {
    let mut info = SERVICE_SID_INFO::default();
    let mut needed = 0;
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut info as *mut SERVICE_SID_INFO).cast(),
            size_of::<SERVICE_SID_INFO>(),
        )
    };
    unsafe {
        QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            Some(bytes),
            &mut needed,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    if info.dwServiceSidType != SERVICE_SID_TYPE_UNRESTRICTED {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

/// Checks a service object's actual owner instead of inferring ownership from its name.
fn verify_service_owner(service: &Service, newly_created: bool) -> Result<(), NativeError> {
    use windows::Win32::Security::*;
    let mut storage = service_query_storage();
    let mut needed = 0;
    let sd = PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast());
    unsafe {
        QueryServiceObjectSecurity(
            service.0,
            OWNER_SECURITY_INFORMATION.0,
            Some(sd),
            (storage.len() * size_of::<usize>()) as u32,
            &mut needed,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let mut owner = PSID::default();
    let mut defaulted = false.into();
    unsafe { GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) }
        .map_err(|_| NativeError::AccessDenied)?;
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(owner, &mut text) }.map_err(|_| NativeError::AccessDenied)?;
    let owner = unsafe { text.to_string() }.map_err(|_| NativeError::AccessDenied);
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    let owner = owner?;
    if !matches!(owner.as_str(), "S-1-5-18" | "S-1-5-32-544")
        && (!newly_created || owner != installer_sid()?)
    {
        return Err(NativeError::AccessDenied);
    }
    // Fresh service objects created by an elevated administrator can inherit
    // that token's owner. Pin built-in Administrators as the permanent owner.
    if newly_created && owner != "S-1-5-32-544" {
        let mut sid = [0u32; 32];
        let mut length = size_of_val(&sid) as u32;
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                None,
                Some(PSID(sid.as_mut_ptr().cast())),
                &mut length,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let pointer = PSECURITY_DESCRIPTOR((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast());
        unsafe { InitializeSecurityDescriptor(pointer, 1) }
            .map_err(|_| NativeError::AccessDenied)?;
        unsafe { SetSecurityDescriptorOwner(pointer, Some(PSID(sid.as_mut_ptr().cast())), false) }
            .map_err(|_| NativeError::AccessDenied)?;
        unsafe { SetServiceObjectSecurity(service.0, OWNER_SECURITY_INFORMATION, pointer) }
            .map_err(|_| NativeError::AccessDenied)?;
        return verify_service_owner(service, false);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    /// Exercises the production allocator against read-only APIs on the Windows
    /// core RPC service. No service configuration or security policy is changed.
    #[test]
    fn service_query_storage_satisfies_both_scm_rpc_limits() {
        let manager = Service(
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
                .expect("read-only SCM query must be available"),
        );
        let name = wide("RpcSs");
        let service = Service(
            unsafe {
                OpenServiceW(
                    manager.0,
                    PCWSTR(name.as_ptr()),
                    SERVICE_QUERY_CONFIG | 0x00020000,
                )
            }
            .expect("core RPC service must allow configuration and owner queries"),
        );
        let mut storage = service_query_storage();
        let capacity = storage.len() * size_of::<usize>();
        let mut needed = 0;
        let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        // SAFETY: storage is aligned, writable, and retained for the whole call.
        let result =
            unsafe { QueryServiceConfigW(service.0, Some(config), capacity as u32, &mut needed) };
        assert!(result.is_ok(), "configuration RPC query failed: {result:?}");
        let descriptor = PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast());
        // SAFETY: the same aligned storage is sufficient for the bounded descriptor.
        let result = unsafe {
            QueryServiceObjectSecurity(
                service.0,
                OWNER_SECURITY_INFORMATION.0,
                Some(descriptor),
                capacity as u32,
                &mut needed,
            )
        };
        assert!(
            result.is_ok(),
            "owner-security RPC query failed: {result:?}"
        );
        assert!(capacity <= MAX_SERVICE_QUERY_BYTES);
    }
}
