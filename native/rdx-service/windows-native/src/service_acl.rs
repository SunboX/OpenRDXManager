// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed Windows service-DACL provisioning for an elevated installer.

use crate::NativeError;
const SERVICE_NAME: &str = "OpenRDXHardwareService";
const LOCAL_SYSTEM_ACCESS: u32 = 0x000F_01FF;
const ADMINISTRATORS_ACCESS: u32 = 0x000F_01FF;
const LOCAL_SERVICE_ACCESS: u32 = 0x0000_0004;
const MANAGER_USER_ACCESS: u32 = 0x0000_0015;
/// Fixed principal roles admitted by the protected service DACL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceDaclPrincipal {
    /// Built-in LocalSystem service authority.
    LocalSystem,
    /// Built-in administrators service authority.
    Administrators,
    /// The service's LocalService account with query-status only.
    LocalService,
    /// The exact active manager user with query-config/query-status/start only.
    ManagerUser,
}
/// One ordered access-allowed entry in the canonical service DACL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDaclEntry {
    /// Fixed semantic principal role.
    pub principal: ServiceDaclPrincipal,
    /// Exact numeric Windows service access mask.
    pub access_mask: u32,
}
const SERVICE_DACL_ENTRIES: [ServiceDaclEntry; 4] = [
    ServiceDaclEntry {
        principal: ServiceDaclPrincipal::LocalSystem,
        access_mask: LOCAL_SYSTEM_ACCESS,
    },
    ServiceDaclEntry {
        principal: ServiceDaclPrincipal::Administrators,
        access_mask: ADMINISTRATORS_ACCESS,
    },
    ServiceDaclEntry {
        principal: ServiceDaclPrincipal::LocalService,
        access_mask: LOCAL_SERVICE_ACCESS,
    },
    ServiceDaclEntry {
        principal: ServiceDaclPrincipal::ManagerUser,
        access_mask: MANAGER_USER_ACCESS,
    },
];
/// Portable fixed service-DACL installation contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDaclContract {
    /// Exact service name; no caller-selected service is accepted.
    pub service_name: &'static str,
    /// Whether inherited ACEs are disabled on the resulting DACL.
    pub protected: bool,
    /// Exact canonical ordered access-allowed entries after provisioning.
    pub entries: &'static [ServiceDaclEntry],
}
/// Returns the canonical protected service-DACL contract.
#[must_use]
pub const fn service_dacl_contract() -> ServiceDaclContract {
    ServiceDaclContract {
        service_name: SERVICE_NAME,
        protected: true,
        entries: &SERVICE_DACL_ENTRIES,
    }
}
/// Fixed elevated-installer operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagerServiceAccessAction {
    /// Materialize or repair the exact four-entry protected DACL.
    Provision,
    /// Verify the exact effective provisioned DACL without mutation.
    Verify,
    /// Remove manager access while retaining the three service authorities.
    Remove,
}
/// Strict provisioner command containing no SID, service name, or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagerServiceAccessCommand {
    action: ManagerServiceAccessAction,
    manager_process_id: u32,
}
impl ManagerServiceAccessCommand {
    /// Returns the fixed requested operation.
    #[must_use]
    pub const fn action(self) -> ManagerServiceAccessAction {
        self.action
    }
    /// Returns the installer-supplied live manager process identifier.
    #[must_use]
    pub const fn manager_process_id(self) -> u32 {
        self.manager_process_id
    }
}
/// Parses the only command form accepted by the installer provisioner.
///
/// # Errors
///
/// Returns [`NativeError::InvalidRequest`] for missing, reordered, extra,
/// non-UTF-8, zero, or out-of-range values.
pub fn parse_manager_service_access_arguments(
    arguments: &[&str],
) -> Result<ManagerServiceAccessCommand, NativeError> {
    if arguments.len() != 4 || arguments[0] != "--action" || arguments[2] != "--manager-process-id"
    {
        return Err(NativeError::InvalidRequest);
    }
    let action = match arguments[1] {
        "provision" => ManagerServiceAccessAction::Provision,
        "verify" => ManagerServiceAccessAction::Verify,
        "remove" => ManagerServiceAccessAction::Remove,
        _ => return Err(NativeError::InvalidRequest),
    };
    let manager_process_id = arguments[3]
        .parse::<u32>()
        .ok()
        .filter(|process_id| *process_id != 0)
        .ok_or(NativeError::InvalidRequest)?;
    Ok(ManagerServiceAccessCommand {
        action,
        manager_process_id,
    })
}
/// Stable successful result of one elevated installer operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagerServiceAccessOutcome {
    /// The provisioned DACL was already exact.
    AlreadyExact,
    /// The protected DACL was changed and re-read exactly.
    Changed,
    /// Verification proved the exact protected provisioned DACL.
    Verified,
    /// Manager access was absent or removed and the base DACL is exact.
    Removed,
}
/// Applies one fixed elevated-installer service access operation.
///
/// The implementation opens only `OpenRDXHardwareService`, derives the manager
/// SID from a live process in the active console session, derives the service
/// binary from the provisioner's own fixed sibling, and accepts no raw path,
/// service, or SID input.
///
/// # Errors
///
/// Returns a sanitized invalid-request, access, identity, or native failure.
pub fn apply_manager_service_access(
    command: ManagerServiceAccessCommand,
) -> Result<ManagerServiceAccessOutcome, NativeError> {
    #[cfg(windows)]
    {
        windows_impl::apply(command)
    }
    #[cfg(not(windows))]
    {
        let _ = command;
        Err(NativeError::UnsupportedPlatform)
    }
}
#[cfg(windows)]
mod windows_helpers;

#[cfg(windows)]
mod windows_impl {
    use super::{
        ADMINISTRATORS_ACCESS, LOCAL_SERVICE_ACCESS, LOCAL_SYSTEM_ACCESS, MANAGER_USER_ACCESS,
        ManagerServiceAccessAction, ManagerServiceAccessCommand, ManagerServiceAccessOutcome,
        SERVICE_NAME,
    };
    use crate::NativeError;
    use crate::registry_acl::{provision_registry_acl, registry_acl_ready};
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::mem::{align_of, size_of, size_of_val};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, HWND};
    use windows::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
        WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_INSTALL, WinVerifyTrust,
    };
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_FLAGS, ACL, ACL_REVISION, AddAccessAllowedAceEx,
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, InitializeAcl,
        InitializeSecurityDescriptor, IsValidAcl, IsValidSid, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
        SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenSessionId, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalServiceSid, WinLocalSystemSid, WinNetworkServiceSid,
    };
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, READ_CONTROL, WRITE_DAC,
    };
    use windows::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    };
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
        QueryServiceConfigW, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
        SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::windows_helpers::{
        bounded_multi_wide, bounded_wide, is_error, map_native_error, wide_null,
    };
    const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 65_536;
    const MAX_SERVICE_CONFIG_BYTES: usize = 65_536;
    const MAX_TOKEN_BYTES: usize = 4_096;
    const SERVICE_ARGUMENTS: &[u16] = &[
        32, 45, 45, 115, 101, 114, 118, 105, 99, 101, 45, 109, 111, 100, 101, 32, 110, 97, 109,
        101, 100, 45, 112, 105, 112, 101, 32, 45, 45, 112, 114, 111, 116, 111, 99, 111, 108, 45,
        118, 101, 114, 115, 105, 111, 110, 32, 49,
    ];
    const STILL_ACTIVE_CODE: u32 = 259;

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        /// Closes one process or token handle exactly once.
        fn drop(&mut self) {
            // SAFETY: this guard exclusively owns a successful non-null handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    struct OwnedService(SC_HANDLE);

    impl Drop for OwnedService {
        /// Closes one SCM or service handle exactly once.
        fn drop(&mut self) {
            // SAFETY: this guard exclusively owns a successful SC_HANDLE.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ServiceConfiguration {
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_command: Vec<u16>,
        account: Vec<u16>,
        dependencies: Vec<u16>,
        load_order_group: Vec<u16>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        volume: u32,
        index_high: u32,
        index_low: u32,
    }

    struct OwnedSid {
        storage: Vec<usize>,
        length: usize,
    }

    impl OwnedSid {
        /// Returns an aligned borrowed SID for one synchronous native call.
        fn pointer(&self) -> PSID {
            PSID(self.storage.as_ptr().cast_mut().cast())
        }

        /// Copies the exact complete SID bytes for deterministic comparison.
        fn bytes(&self) -> &[u8] {
            // SAFETY: storage remains live and length was validated against its capacity.
            unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast(), self.length) }
        }
    }

    /// Runs one fail-closed service access operation.
    pub(super) fn apply(
        command: ManagerServiceAccessCommand,
    ) -> Result<ManagerServiceAccessOutcome, NativeError> {
        let (expected_binary, expected_identity, expected_manager, expected_manager_identity) =
            expected_package_binaries()?;
        let manager_process = open_manager_process(command.manager_process_id())?;
        validate_manager_process(
            &manager_process,
            command.manager_process_id(),
            &expected_manager,
            expected_manager_identity,
        )?;
        let manager_user_sid = manager_sid(&manager_process, command.manager_process_id())?;
        let service = open_fixed_service()?;
        let baseline = query_service_configuration(&service)?;
        validate_service_configuration(&baseline, &expected_binary, expected_identity)?;
        validate_existing_dacl(&read_service_security(&service)?)?;

        // The exact registry root is created with its final descriptor in one
        // kernel call before the paired service DACL changes. A newly created
        // empty root is rolled back unless every service/registry recheck passes.
        let registry_provisioning = match command.action() {
            ManagerServiceAccessAction::Provision => Some(provision_registry_acl()?),
            ManagerServiceAccessAction::Verify | ManagerServiceAccessAction::Remove => {
                if !registry_acl_ready() {
                    return Err(NativeError::AccessDenied);
                }
                None
            }
        };

        let include_manager = command.action() != ManagerServiceAccessAction::Remove;
        let already_exact = exact_dacl_matches(&service, &manager_user_sid, include_manager)?;
        let outcome = match command.action() {
            ManagerServiceAccessAction::Verify => {
                if !already_exact {
                    return Err(NativeError::AccessDenied);
                }
                ManagerServiceAccessOutcome::Verified
            }
            ManagerServiceAccessAction::Provision if already_exact => {
                ManagerServiceAccessOutcome::AlreadyExact
            }
            ManagerServiceAccessAction::Remove if already_exact => {
                ManagerServiceAccessOutcome::Removed
            }
            ManagerServiceAccessAction::Provision | ManagerServiceAccessAction::Remove => {
                set_exact_dacl(&service, &manager_user_sid, include_manager)?;
                if !exact_dacl_matches(&service, &manager_user_sid, include_manager)? {
                    return Err(NativeError::AccessDenied);
                }
                if include_manager {
                    ManagerServiceAccessOutcome::Changed
                } else {
                    ManagerServiceAccessOutcome::Removed
                }
            }
        };

        let confirmed = query_service_configuration(&service)?;
        validate_service_configuration(&confirmed, &expected_binary, expected_identity)?;
        validate_manager_process(
            &manager_process,
            command.manager_process_id(),
            &expected_manager,
            expected_manager_identity,
        )?;
        if baseline != confirmed
            || manager_sid(&manager_process, command.manager_process_id())?.bytes()
                != manager_user_sid.bytes()
        {
            return Err(NativeError::AccessDenied);
        }
        if !registry_acl_ready() {
            return Err(NativeError::AccessDenied);
        }
        if let Some(provisioning) = registry_provisioning {
            provisioning.commit();
        }
        Ok(outcome)
    }

    /// Opens and pins the live active-console process selected by the installer.
    fn open_manager_process(process_id: u32) -> Result<OwnedHandle, NativeError> {
        // SAFETY: the exact nonzero PID is opened query-only and immediately owned.
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
            .map(OwnedHandle)
            .map_err(map_native_error)
    }

    /// Revalidates active session, liveness, and exact installed manager identity.
    fn validate_manager_process(
        process: &OwnedHandle,
        process_id: u32,
        expected_manager: &Path,
        expected_identity: FileIdentity,
    ) -> Result<(), NativeError> {
        let mut process_session = u32::MAX;
        let active_session = {
            // SAFETY: this query has no pointer or ownership preconditions.
            unsafe { WTSGetActiveConsoleSessionId() }
        };
        // SAFETY: output points to initialized writable scalar storage.
        unsafe { ProcessIdToSessionId(process_id, &mut process_session) }
            .map_err(map_native_error)?;
        if active_session == u32::MAX || process_session != active_session {
            return Err(NativeError::AccessDenied);
        }
        let mut exit_code = 0_u32;
        // SAFETY: process is live and output is valid writable scalar storage.
        unsafe { GetExitCodeProcess(process.0, &mut exit_code) }.map_err(map_native_error)?;
        if exit_code != STILL_ACTIVE_CODE {
            return Err(NativeError::AccessDenied);
        }
        let mut image = vec![0_u16; 32_768];
        let mut image_length = image.len() as u32;
        // SAFETY: process is query-owned and output is bounded writable UTF-16 storage.
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_WIN32,
                PWSTR(image.as_mut_ptr()),
                &mut image_length,
            )
        }
        .map_err(map_native_error)?;
        if image_length == 0 || image_length as usize >= image.len() {
            return Err(NativeError::AccessDenied);
        }
        let observed_manager = PathBuf::from(OsString::from_wide(&image[..image_length as usize]));
        if file_identity(&observed_manager)? != expected_identity
            || file_identity(expected_manager)? != expected_identity
        {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Derives and validates the exact active-console user SID from a pinned process.
    fn manager_sid(process: &OwnedHandle, process_id: u32) -> Result<OwnedSid, NativeError> {
        let mut token = HANDLE::default();
        // SAFETY: process is query-owned, TOKEN_QUERY is read-only, and output is writable.
        unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) }
            .map_err(map_native_error)?;
        let token = OwnedHandle(token);
        let mut token_session = u32::MAX;
        let mut returned = 0_u32;
        // SAFETY: output is exact writable u32 storage for TokenSessionId.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenSessionId,
                Some((&mut token_session as *mut u32).cast()),
                size_of::<u32>() as u32,
                &mut returned,
            )
        }
        .map_err(map_native_error)?;
        let mut process_session = u32::MAX;
        // SAFETY: output points to initialized writable scalar storage.
        unsafe { ProcessIdToSessionId(process_id, &mut process_session) }
            .map_err(map_native_error)?;
        // SAFETY: this query has no pointer or ownership preconditions.
        if returned as usize != size_of::<u32>()
            || token_session != process_session
            || token_session != unsafe { WTSGetActiveConsoleSessionId() }
        {
            return Err(NativeError::AccessDenied);
        }
        let sid = token_user_sid(&token)?;
        for forbidden in [
            WinLocalSystemSid,
            WinLocalServiceSid,
            WinNetworkServiceSid,
            WinBuiltinAdministratorsSid,
        ] {
            if sid.bytes() == well_known_sid(forbidden)?.bytes() {
                return Err(NativeError::AccessDenied);
            }
        }
        Ok(sid)
    }

    /// Copies one variable-length token user SID into aligned owned storage.
    fn token_user_sid(token: &OwnedHandle) -> Result<OwnedSid, NativeError> {
        let mut needed = 0_u32;
        // SAFETY: null output with zero size is the documented sizing query.
        let sizing = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
        if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
            || !(size_of::<TOKEN_USER>()..=MAX_TOKEN_BYTES).contains(&(needed as usize))
        {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = storage.len() * size_of::<usize>();
        // SAFETY: aligned storage is writable for its exact bounded capacity.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(storage.as_mut_ptr().cast()),
                capacity as u32,
                &mut needed,
            )
        }
        .map_err(map_native_error)?;
        if !(size_of::<TOKEN_USER>()..=capacity).contains(&(needed as usize)) {
            return Err(NativeError::Other);
        }
        // SAFETY: the successful query initialized the aligned TOKEN_USER prefix.
        let user = unsafe { storage.as_ptr().cast::<TOKEN_USER>().read() };
        copy_bounded_sid(user.User.Sid, storage.as_ptr() as usize, needed as usize)
    }

    /// Creates one aligned owned built-in SID.
    fn well_known_sid(
        kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE,
    ) -> Result<OwnedSid, NativeError> {
        let mut storage =
            vec![0_usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>())];
        let mut length = (storage.len() * size_of::<usize>()) as u32;
        // SAFETY: aligned storage is writable for its declared capacity.
        unsafe {
            CreateWellKnownSid(
                kind,
                None,
                Some(PSID(storage.as_mut_ptr().cast())),
                &mut length,
            )
        }
        .map_err(map_native_error)?;
        if length == 0 || length as usize > storage.len() * size_of::<usize>() {
            return Err(NativeError::Other);
        }
        Ok(OwnedSid {
            storage,
            length: length as usize,
        })
    }

    /// Bounds and copies a SID returned inside one native allocation.
    fn copy_bounded_sid(
        sid: PSID,
        allocation_start: usize,
        allocation_length: usize,
    ) -> Result<OwnedSid, NativeError> {
        let address = sid.0 as usize;
        let allocation_end = allocation_start
            .checked_add(allocation_length)
            .ok_or(NativeError::ResourceLimit)?;
        if address < allocation_start
            || address
                .checked_add(8)
                .is_none_or(|end| end > allocation_end)
            || address % align_of::<u32>() != 0
        {
            return Err(NativeError::Other);
        }
        // SAFETY: the fixed SID header is bounded inside the live allocation.
        let count = unsafe { *(address as *const u8).add(1) } as usize;
        let length = 8_usize
            .checked_add(count.checked_mul(4).ok_or(NativeError::ResourceLimit)?)
            .ok_or(NativeError::ResourceLimit)?;
        if address
            .checked_add(length)
            .is_none_or(|end| end > allocation_end)
        {
            return Err(NativeError::Other);
        }
        // SAFETY: the complete computed SID is bounded before native validation.
        if unsafe { !IsValidSid(sid).as_bool() } {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; length.div_ceil(size_of::<usize>())];
        // SAFETY: source and destination are disjoint and valid for exact SID bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                address as *const u8,
                storage.as_mut_ptr().cast::<u8>(),
                length,
            )
        };
        Ok(OwnedSid { storage, length })
    }

    /// Resolves fixed package binaries and verifies the installed manager signature.
    fn expected_package_binaries()
    -> Result<(PathBuf, FileIdentity, PathBuf, FileIdentity), NativeError> {
        let provisioner = std::env::current_exe().map_err(|_| NativeError::Other)?;
        let native_windows = provisioner.parent().ok_or(NativeError::Other)?;
        let resources = native_windows
            .parent()
            .and_then(|native| native.parent())
            .ok_or(NativeError::Other)?;
        let install_root = resources.parent().ok_or(NativeError::Other)?;
        let service_binary = native_windows.join("openrdx-hardware.exe");
        let manager_binary = install_root.join("OpenRDXManager.exe");
        let service_identity = file_identity(&service_binary)?;
        let manager_identity = file_identity(&manager_binary)?;
        verify_trusted_signature(&manager_binary)?;
        Ok((
            service_binary,
            service_identity,
            manager_binary,
            manager_identity,
        ))
    }

    /// Requires a noninteractive trusted Authenticode signature on the installed manager.
    fn verify_trusted_signature(path: &Path) -> Result<(), NativeError> {
        let path = wide_null(path.as_os_str());
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(path.as_ptr()),
            ..Default::default()
        };
        let mut trust = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
                | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                | WTD_DISABLE_MD2_MD4,
            dwUIContext: WTD_UICONTEXT_INSTALL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: action, trust, file, and path storage remain live for the synchronous call.
        let status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                (&mut trust as *mut WINTRUST_DATA).cast(),
            )
        };
        trust.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: closes only the state created by the immediately preceding trust call.
        let _ = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                (&mut trust as *mut WINTRUST_DATA).cast(),
            )
        };
        if status != 0 {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Reads the stable Windows file identity of one fixed package path.
    fn file_identity(path: &Path) -> Result<FileIdentity, NativeError> {
        let file = File::open(path).map_err(|_| NativeError::Other)?;
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the borrowed file handle remains live and output is writable.
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
            .map_err(map_native_error)?;
        Ok(FileIdentity {
            volume: information.dwVolumeSerialNumber,
            index_high: information.nFileIndexHigh,
            index_low: information.nFileIndexLow,
        })
    }

    /// Opens only the fixed service with query plus DACL mutation authority.
    fn open_fixed_service() -> Result<OwnedService, NativeError> {
        // SAFETY: null names select only the local active SCM database.
        let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map(OwnedService)
            .map_err(map_native_error)?;
        let name = wide_null(OsStr::new(SERVICE_NAME));
        let access = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL.0 | WRITE_DAC.0;
        // SAFETY: name is exact NUL-terminated fixed storage and manager remains live.
        unsafe { OpenServiceW(manager.0, PCWSTR(name.as_ptr()), access) }
            .map(OwnedService)
            .map_err(map_native_error)
    }

    /// Queries one bounded service configuration with validated embedded pointers.
    fn query_service_configuration(
        service: &OwnedService,
    ) -> Result<ServiceConfiguration, NativeError> {
        let mut needed = 0_u32;
        // SAFETY: null output with zero length is the documented sizing query.
        let sizing = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
        if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
            || !(size_of::<QUERY_SERVICE_CONFIGW>()..=MAX_SERVICE_CONFIG_BYTES)
                .contains(&(needed as usize))
        {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = storage.len() * size_of::<usize>();
        let pointer = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        // SAFETY: aligned storage is writable and remains live for pointer validation.
        unsafe { QueryServiceConfigW(service.0, Some(pointer), capacity as u32, &mut needed) }
            .map_err(map_native_error)?;
        if !(size_of::<QUERY_SERVICE_CONFIGW>()..=capacity).contains(&(needed as usize)) {
            return Err(NativeError::Other);
        }
        // SAFETY: successful query initialized the aligned leading configuration.
        let config = unsafe { pointer.read() };
        Ok(ServiceConfiguration {
            service_type: config.dwServiceType.0,
            start_type: config.dwStartType.0,
            error_control: config.dwErrorControl.0,
            binary_command: bounded_wide(&storage, needed as usize, config.lpBinaryPathName.0)?,
            account: bounded_wide(&storage, needed as usize, config.lpServiceStartName.0)?,
            dependencies: bounded_multi_wide(&storage, needed as usize, config.lpDependencies.0)?,
            load_order_group: bounded_wide(&storage, needed as usize, config.lpLoadOrderGroup.0)?,
        })
    }

    /// Validates the immutable service identity and exact sibling binary file.
    fn validate_service_configuration(
        config: &ServiceConfiguration,
        expected_binary: &Path,
        expected_identity: FileIdentity,
    ) -> Result<(), NativeError> {
        let path = expected_binary
            .as_os_str()
            .encode_wide()
            .collect::<Vec<_>>();
        let mut command = Vec::with_capacity(path.len() + SERVICE_ARGUMENTS.len() + 2);
        command.push(u16::from(b'"'));
        command.extend_from_slice(&path);
        command.push(u16::from(b'"'));
        command.extend_from_slice(SERVICE_ARGUMENTS);
        let account = OsStr::new("NT AUTHORITY\\LocalService")
            .encode_wide()
            .collect::<Vec<_>>();
        if config.service_type != SERVICE_WIN32_OWN_PROCESS.0
            || config.start_type != SERVICE_DEMAND_START.0
            || config.error_control != SERVICE_ERROR_NORMAL.0
            || config.binary_command != command
            || config.account != account
            || !config.dependencies.is_empty()
            || !config.load_order_group.is_empty()
            || file_identity(expected_binary)? != expected_identity
        {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Reads one bounded service security descriptor.
    fn read_service_security(service: &OwnedService) -> Result<Vec<usize>, NativeError> {
        let mut needed = 0_u32;
        // SAFETY: null output with zero length is the documented sizing query.
        let sizing = unsafe {
            windows::Win32::System::Services::QueryServiceObjectSecurity(
                service.0,
                DACL_SECURITY_INFORMATION.0,
                None,
                0,
                &mut needed,
            )
        };
        if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
            || !(size_of::<SECURITY_DESCRIPTOR>()..=MAX_SECURITY_DESCRIPTOR_BYTES)
                .contains(&(needed as usize))
        {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = storage.len() * size_of::<usize>();
        // SAFETY: aligned storage is writable for its bounded exact capacity.
        unsafe {
            windows::Win32::System::Services::QueryServiceObjectSecurity(
                service.0,
                DACL_SECURITY_INFORMATION.0,
                Some(PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast())),
                capacity as u32,
                &mut needed,
            )
        }
        .map_err(map_native_error)?;
        if !(size_of::<SECURITY_DESCRIPTOR>()..=capacity).contains(&(needed as usize)) {
            return Err(NativeError::Other);
        }
        Ok(storage)
    }

    /// Requires the existing service DACL to be present and structurally valid.
    fn validate_existing_dacl(storage: &[usize]) -> Result<(), NativeError> {
        let descriptor = PSECURITY_DESCRIPTOR(storage.as_ptr().cast_mut().cast());
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut acl = std::ptr::null_mut();
        // SAFETY: descriptor is aligned live storage returned by the service API.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            .map_err(map_native_error)?;
        // SAFETY: non-null ACL belongs to the still-live descriptor allocation.
        if !present.as_bool() || acl.is_null() || unsafe { !IsValidAcl(acl).as_bool() } {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Re-reads and compares the exact canonical protected DACL.
    fn exact_dacl_matches(
        service: &OwnedService,
        manager: &OwnedSid,
        include_manager: bool,
    ) -> Result<bool, NativeError> {
        let storage = read_service_security(service)?;
        let descriptor = PSECURITY_DESCRIPTOR(storage.as_ptr().cast_mut().cast());
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: descriptor is aligned live storage returned by the service API.
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
            .map_err(map_native_error)?;
        if revision != 1 || control & SE_DACL_PROTECTED.0 == 0 {
            return Ok(false);
        }
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut acl = std::ptr::null_mut();
        // SAFETY: descriptor is aligned live storage returned by the service API.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            .map_err(map_native_error)?;
        // SAFETY: non-null ACL belongs to the still-live descriptor allocation.
        if !present.as_bool() || acl.is_null() || unsafe { !IsValidAcl(acl).as_bool() } {
            return Err(NativeError::AccessDenied);
        }
        if defaulted.as_bool() {
            return Ok(false);
        }
        let system = well_known_sid(WinLocalSystemSid)?;
        let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        let local_service = well_known_sid(WinLocalServiceSid)?;
        let mut expected = vec![
            (system.bytes(), LOCAL_SYSTEM_ACCESS),
            (administrators.bytes(), ADMINISTRATORS_ACCESS),
            (local_service.bytes(), LOCAL_SERVICE_ACCESS),
        ];
        if include_manager {
            expected.push((manager.bytes(), MANAGER_USER_ACCESS));
        }
        // SAFETY: ACL was validated and its header belongs to live descriptor storage.
        if unsafe { (*acl).AceCount as usize } != expected.len() {
            return Ok(false);
        }
        for (index, (expected_sid, expected_mask)) in expected.into_iter().enumerate() {
            let mut raw_ace = std::ptr::null_mut();
            // SAFETY: index is strictly below the validated ACL's exact AceCount.
            unsafe { GetAce(acl, index as u32, &mut raw_ace) }.map_err(map_native_error)?;
            if raw_ace.is_null() {
                return Err(NativeError::Other);
            }
            let descriptor_start = storage.as_ptr() as usize;
            let descriptor_end = descriptor_start
                .checked_add(size_of_val(storage.as_slice()))
                .ok_or(NativeError::ResourceLimit)?;
            let raw_ace_address = raw_ace as usize;
            if raw_ace_address < descriptor_start
                || raw_ace_address
                    .checked_add(size_of::<ACCESS_ALLOWED_ACE>())
                    .is_none_or(|end| end > descriptor_end)
            {
                return Err(NativeError::AccessDenied);
            }
            // SAFETY: GetAce returned a pointer to at least an ACE header in the valid ACL.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid_pointer = PSID((&raw const ace.SidStart).cast_mut().cast());
            let sid = sid_bytes_in_descriptor(&storage, sid_pointer)?;
            let expected_ace_size = size_of::<ACCESS_ALLOWED_ACE>()
                .checked_sub(size_of::<u32>())
                .and_then(|base| base.checked_add(sid.len()))
                .ok_or(NativeError::ResourceLimit)?;
            if ace.Header.AceType != 0
                || ace.Header.AceFlags != 0
                || ace.Header.AceSize as usize != expected_ace_size
                || ace.Mask != expected_mask
                || sid != expected_sid
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Builds and installs the exact protected access-allowed DACL.
    fn set_exact_dacl(
        service: &OwnedService,
        manager: &OwnedSid,
        include_manager: bool,
    ) -> Result<(), NativeError> {
        let system = well_known_sid(WinLocalSystemSid)?;
        let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        let local_service = well_known_sid(WinLocalServiceSid)?;
        let mut entries = vec![
            (&system, LOCAL_SYSTEM_ACCESS),
            (&administrators, ADMINISTRATORS_ACCESS),
            (&local_service, LOCAL_SERVICE_ACCESS),
        ];
        if include_manager {
            entries.push((manager, MANAGER_USER_ACCESS));
        }
        let acl_bytes = entries
            .iter()
            .try_fold(size_of::<ACL>(), |total, (sid, _)| {
                total
                    .checked_add(size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>())
                    .and_then(|total| total.checked_add(sid.length))
                    .ok_or(NativeError::ResourceLimit)
            })?;
        let mut acl_storage = vec![0_usize; acl_bytes.div_ceil(size_of::<usize>())];
        let acl = acl_storage.as_mut_ptr().cast::<ACL>();
        // SAFETY: aligned ACL storage is writable for the declared bounded capacity.
        unsafe { InitializeAcl(acl, acl_bytes as u32, ACL_REVISION) }.map_err(map_native_error)?;
        for (sid, mask) in entries {
            // SAFETY: ACL remains live with sufficient precomputed capacity and SID is valid.
            unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, ACE_FLAGS(0), mask, sid.pointer()) }
                .map_err(map_native_error)?;
        }
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor_pointer =
            PSECURITY_DESCRIPTOR((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast());
        // SAFETY: descriptor is exact writable SECURITY_DESCRIPTOR storage.
        unsafe { InitializeSecurityDescriptor(descriptor_pointer, 1) }.map_err(map_native_error)?;
        // SAFETY: descriptor and ACL remain live throughout the synchronous setter.
        unsafe { SetSecurityDescriptorDacl(descriptor_pointer, true, Some(acl), false) }
            .map_err(map_native_error)?;
        // SAFETY: service is the fixed query/WRITE_DAC handle and descriptor owns exact ACL.
        unsafe {
            SetServiceObjectSecurity(
                service.0,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor_pointer,
            )
        }
        .map_err(map_native_error)
    }

    /// Copies one SID slice after bounding it inside a returned descriptor.
    fn sid_bytes_in_descriptor(storage: &[usize], sid: PSID) -> Result<&[u8], NativeError> {
        let start = storage.as_ptr() as usize;
        let length = size_of_val(storage);
        let address = sid.0 as usize;
        let end = start
            .checked_add(length)
            .ok_or(NativeError::ResourceLimit)?;
        if address < start || address.checked_add(8).is_none_or(|value| value > end) {
            return Err(NativeError::AccessDenied);
        }
        // SAFETY: the fixed SID header is bounded inside the live descriptor.
        let count = unsafe { *(address as *const u8).add(1) } as usize;
        let sid_length = 8_usize
            .checked_add(count.checked_mul(4).ok_or(NativeError::ResourceLimit)?)
            .ok_or(NativeError::ResourceLimit)?;
        if address
            .checked_add(sid_length)
            .is_none_or(|value| value > end)
        {
            return Err(NativeError::AccessDenied);
        }
        // SAFETY: complete SID bytes are bounded inside live descriptor storage.
        Ok(unsafe { std::slice::from_raw_parts(address as *const u8, sid_length) })
    }
}
