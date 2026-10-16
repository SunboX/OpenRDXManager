// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query-only Windows service and current-process authority evidence.

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::mem::{align_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Security::{
    CreateWellKnownSid, GetTokenInformation, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER,
    TokenUser, WinLocalServiceSid,
};
use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_STATUS_PROCESS, SERVICE_WIN32_OWN_PROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::PCWSTR;

use super::super::{
    AuthorityEvidence, Readiness, ResourceCloser, ResourceGuard, ServiceIdentityEvidence,
    ServiceRuntimeEvidence, ServiceStatusQueryAction, ServiceStatusQueryResult,
    exact_endpoint_service_binary_path, service_status_query_action,
};
use super::{KernelHandle, kernel_handle, win32_error_code};

const SERVICE_NAME: &str = "OpenRDXHardwareService";
const MAX_SERVICE_CONFIG_BYTES: usize = 65_536;
const MAX_TOKEN_USER_BYTES: usize = 4_096;

/// Checks endpoint startup authority while retaining the exact enrolled runtime.
pub(crate) fn verify_service_startup()
-> Result<crate::local_trust::windows::RuntimeLease, crate::NativeError> {
    use crate::service::diagnostics::{Stage, record};
    let trust = record(
        Stage::RuntimeTrust,
        crate::local_trust::verify_runtime_lease(),
    )?;
    if !collect_service_identity(AuthorityPhase::Startup).startup_authorized() {
        return record(
            Stage::StartupAuthority,
            Err(crate::NativeError::AccessDenied),
        );
    }
    if !current_process_is_fixed_service() {
        return record(Stage::ServiceProcess, Err(crate::NativeError::AccessDenied));
    }
    Ok(trust)
}

/// Startup may query the current primary token, never an SCM pending-state PID.
enum AuthorityPhase {
    Startup,
    Running,
}

struct ServiceHandleCloser;

impl ResourceCloser<isize> for ServiceHandleCloser {
    /// Releases one service-control-manager handle exactly once.
    fn close(resource: isize) {
        // SAFETY: ResourceGuard owns the non-invalid SC_HANDLE exactly once.
        let _ = unsafe { CloseServiceHandle(SC_HANDLE(resource as *mut c_void)) };
    }
}

type ServiceHandle = ResourceGuard<isize, ServiceHandleCloser>;

#[derive(Clone, Default, Eq, PartialEq)]
struct ServiceConfigEvidence {
    service_type: u32,
    start_type: u32,
    tag_id: u32,
    binary_command: String,
    account_name: String,
    demand_start: bool,
    binary_matches: bool,
    exact_contract: bool,
}

/// Probes metadata and authority without installing, starting, or mutating a service.
pub(super) fn probe_readiness(adapter_available: bool) -> Readiness {
    let service = service_identity_evidence();
    Readiness::from_authority(
        adapter_available,
        AuthorityEvidence {
            service,
            process_elevated: false,
            // Direct authority is recipe-specific and is therefore unavailable
            // during a global readiness probe. A service-process binding is
            // required until a future endpoint can retain exact access proof.
            exact_device_access: false,
        },
    )
}

/// Collects stable PID and constrained configuration evidence for the expected service.
fn service_identity_evidence() -> ServiceIdentityEvidence {
    collect_service_identity(AuthorityPhase::Running)
}

/// Collects shared fixed configuration facts with phase-specific process provenance.
fn collect_service_identity(phase: AuthorityPhase) -> ServiceIdentityEvidence {
    // SAFETY: GetCurrentProcessId has no pointer or ownership preconditions.
    let current_pid = unsafe { GetCurrentProcessId() };
    let mut evidence = ServiceIdentityEvidence {
        installed: false,
        current_pid,
        status_before: unavailable_runtime_status(),
        status_after: unavailable_runtime_status(),
        config_stable: false,
        demand_start: false,
        binary_matches: false,
        token_local_service: false,
    };

    // SAFETY: null names select the local active service database read-only.
    let manager =
        match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
            Ok(handle) => ServiceHandle::new(handle.0 as isize),
            Err(_) => return evidence,
        };
    let service_name = wide_null(OsStr::new(SERVICE_NAME));
    // SAFETY: service_name is NUL-terminated and access is query-only.
    let service = match unsafe {
        OpenServiceW(
            service_handle(&manager),
            PCWSTR(service_name.as_ptr()),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    } {
        Ok(handle) => ServiceHandle::new(handle.0 as isize),
        Err(_) => return evidence,
    };
    evidence.installed = true;

    let status_before = query_service_status(&service);
    let config_before = query_service_config(&service);
    let token_pid = match phase {
        // QueryServiceStatusEx explicitly does not guarantee dwProcessId during
        // START_PENDING. Only the private SCM callback may select this branch.
        // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex
        AuthorityPhase::Startup => Some(current_pid),
        AuthorityPhase::Running => status_before
            .as_ref()
            .filter(|status| status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0)
            .map(|status| status.dwProcessId),
    };
    let token_local_service = token_pid.is_some_and(|process_id| {
        process_token_is_local_service(process_id)
            && crate::local_trust::windows::service_sid_enabled(process_id).unwrap_or(false)
    });
    let config_after = query_service_config(&service);
    let status_after = query_service_status(&service);

    if let Some(status) = status_before {
        evidence.status_before = runtime_status(status);
    }
    if let Some(status) = status_after {
        evidence.status_after = runtime_status(status);
    }
    if let (Some(before), Some(after)) = (config_before, config_after) {
        evidence.config_stable = before == after
            && before.exact_contract
            && crate::registry_acl::registry_acl_ready()
            && crate::verify_installed_local_trust().is_ok();
        if evidence.config_stable {
            evidence.demand_start = before.demand_start;
            evidence.binary_matches = before.binary_matches;
        }
    }
    evidence.token_local_service = token_local_service;
    evidence
}

/// Converts status fields into the portable runtime-only authority snapshot.
fn runtime_status(status: SERVICE_STATUS_PROCESS) -> ServiceRuntimeEvidence {
    ServiceRuntimeEvidence {
        running: status.dwCurrentState == SERVICE_RUNNING,
        process_id: status.dwProcessId,
        own_process: status.dwServiceType == SERVICE_WIN32_OWN_PROCESS,
    }
}

/// Returns the fail-closed placeholder for a missing status query.
const fn unavailable_runtime_status() -> ServiceRuntimeEvidence {
    ServiceRuntimeEvidence {
        running: false,
        process_id: 0,
        own_process: false,
    }
}

/// Queries one exact process-status snapshot from the read-only service handle.
fn query_service_status(service: &ServiceHandle) -> Option<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0_u32;
    // SAFETY: status is valid writable storage viewed as its exact byte length.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&raw mut status).cast::<u8>(),
            size_of::<SERVICE_STATUS_PROCESS>(),
        )
    };
    // SAFETY: service is query-authorized and bytes covers SERVICE_STATUS_PROCESS.
    let result = unsafe {
        QueryServiceStatusEx(
            service_handle(service),
            SC_STATUS_PROCESS_INFO,
            Some(bytes),
            &mut needed,
        )
    };
    match service_status_query_action(service_status_query_result(&result), needed, bytes.len()) {
        ServiceStatusQueryAction::Accept => Some(status),
        ServiceStatusQueryAction::Retry(required) => {
            let mut storage = vec![0_usize; required.div_ceil(size_of::<usize>())];
            let capacity = storage.len().checked_mul(size_of::<usize>())?;
            let mut retry_needed = 0_u32;
            // SAFETY: aligned storage is writable for its exact bounded capacity.
            let retry = unsafe {
                QueryServiceStatusEx(
                    service_handle(service),
                    SC_STATUS_PROCESS_INFO,
                    Some(std::slice::from_raw_parts_mut(
                        storage.as_mut_ptr().cast::<u8>(),
                        capacity,
                    )),
                    &mut retry_needed,
                )
            };
            if service_status_query_action(
                service_status_query_result(&retry),
                retry_needed,
                capacity,
            ) != ServiceStatusQueryAction::Accept
            {
                return None;
            }
            // SAFETY: successful QueryServiceStatusEx initialized the leading
            // SERVICE_STATUS_PROCESS regardless of pcbBytesNeeded's value.
            Some(unsafe { storage.as_ptr().cast::<SERVICE_STATUS_PROCESS>().read() })
        }
        ServiceStatusQueryAction::Reject => None,
    }
}

/// Maps only documented status-query control flow without retaining error text.
fn service_status_query_result(result: &windows::core::Result<()>) -> ServiceStatusQueryResult {
    match result {
        Ok(()) => ServiceStatusQueryResult::Success,
        Err(error) if win32_error_code(error) == Some(ERROR_INSUFFICIENT_BUFFER) => {
            ServiceStatusQueryResult::InsufficientBuffer
        }
        Err(_) => ServiceStatusQueryResult::Failure,
    }
}

/// Reads the bounded variable-length configuration and validates all embedded pointers.
fn query_service_config(service: &ServiceHandle) -> Option<ServiceConfigEvidence> {
    let mut needed = 0_u32;
    // SAFETY: a null output with zero size is the documented sizing query.
    let sizing = unsafe { QueryServiceConfigW(service_handle(service), None, 0, &mut needed) };
    if !matches!(
        sizing.as_ref().err().and_then(win32_error_code),
        Some(ERROR_INSUFFICIENT_BUFFER)
    ) {
        return None;
    }
    let required = needed as usize;
    if !(size_of::<QUERY_SERVICE_CONFIGW>()..=MAX_SERVICE_CONFIG_BYTES).contains(&required) {
        return None;
    }
    let words = required.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let capacity = storage.len().checked_mul(size_of::<usize>())?;
    let config_pointer = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: storage is pointer-aligned, writable for capacity bytes, and remains
    // alive while every returned in-buffer pointer is inspected.
    unsafe {
        QueryServiceConfigW(
            service_handle(service),
            Some(config_pointer),
            u32::try_from(capacity).ok()?,
            &mut needed,
        )
    }
    .ok()?;
    // SAFETY: the successful API call initialized the leading aligned structure.
    let config = unsafe { config_pointer.read() };
    let binary = bounded_config_string(&storage, config.lpBinaryPathName.0)?;
    let account = bounded_config_string(&storage, config.lpServiceStartName.0)?;
    let exact_command = format!(
        "\"{}\" --service-mode named-pipe --protocol-version 1",
        crate::local_trust::LOCAL_SERVICE_BINARY
    );
    let exact_contract = config.dwServiceType == SERVICE_WIN32_OWN_PROCESS
        && config.dwStartType == SERVICE_DEMAND_START
        && config.dwErrorControl == SERVICE_ERROR_NORMAL
        && config.dwTagId == 0
        && binary == exact_command
        && account == "NT AUTHORITY\\LocalService"
        && bounded_config_string(&storage, config.lpDisplayName.0)? == "OpenRDX Hardware Service"
        && bounded_optional_config_string(&storage, config.lpLoadOrderGroup.0)?.is_empty()
        && bounded_optional_config_string(&storage, config.lpDependencies.0)?.is_empty();

    Some(ServiceConfigEvidence {
        service_type: config.dwServiceType.0,
        start_type: config.dwStartType.0,
        tag_id: config.dwTagId,
        binary_command: binary.clone(),
        account_name: account,
        demand_start: config.dwStartType == SERVICE_DEMAND_START,
        binary_matches: service_binary_matches_current_process(&binary),
        exact_contract,
    })
}

/// Opens only the running PID for query and proves its primary token is LocalService.
fn process_token_is_local_service(process_id: u32) -> bool {
    // SAFETY: the nonzero PID is queried with the least process access required
    // to open its token; the returned handle is owned immediately by RAII.
    let process = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
    {
        Ok(handle) => KernelHandle::new(handle.0 as isize),
        Err(_) => return false,
    };
    let mut token = HANDLE::default();
    // SAFETY: process remains live, TOKEN_QUERY is read-only, and token is writable output.
    if unsafe { OpenProcessToken(kernel_handle(&process), TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let token = KernelHandle::new(token.0 as isize);
    token_user_is_local_service(kernel_handle(&token))
}

/// Copies and bounds `TOKEN_USER`, then compares its complete SID bytes.
fn token_user_is_local_service(token: HANDLE) -> bool {
    let mut needed = 0_u32;
    // SAFETY: a null output with zero length is the documented sizing query.
    let sizing = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if !matches!(
        sizing.as_ref().err().and_then(win32_error_code),
        Some(ERROR_INSUFFICIENT_BUFFER)
    ) {
        return false;
    }
    let required = needed as usize;
    if !(size_of::<TOKEN_USER>()..=MAX_TOKEN_USER_BYTES).contains(&required) {
        return false;
    }
    let mut storage = vec![0_usize; required.div_ceil(size_of::<usize>())];
    let capacity = storage.len().saturating_mul(size_of::<usize>());
    let Ok(capacity_u32) = u32::try_from(capacity) else {
        return false;
    };
    // SAFETY: aligned storage remains writable for capacity bytes during the query.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            capacity_u32,
            &mut needed,
        )
    }
    .is_err()
        || !(size_of::<TOKEN_USER>()..=capacity).contains(&(needed as usize))
    {
        return false;
    }
    let token_user_pointer = storage.as_ptr().cast::<TOKEN_USER>();
    // SAFETY: storage is pointer-aligned and the successful query initialized
    // at least the leading TOKEN_USER structure proven by the sizing bound.
    let token_user = unsafe { token_user_pointer.read() };
    let base = storage.as_ptr() as usize;
    let end = match base.checked_add(needed as usize) {
        Some(end) => end,
        None => return false,
    };
    let sid_address = token_user.User.Sid.0 as usize;
    let sid_start = match base.checked_add(size_of::<TOKEN_USER>()) {
        Some(start) => start,
        None => return false,
    };
    if sid_address < sid_start || sid_address >= end || sid_address % align_of::<u32>() != 0 {
        return false;
    }
    let sid_offset = sid_address - base;
    // SAFETY: the pointer was bounded inside live storage; bytes is limited to
    // the remaining allocation before any variable SID length is inspected.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>().add(sid_offset),
            end - sid_address,
        )
    };
    let Some(subauthority_count) = bytes.get(1).copied() else {
        return false;
    };
    let Some(sid_length) = 8_usize.checked_add(usize::from(subauthority_count).saturating_mul(4))
    else {
        return false;
    };
    let Some(user_sid) = bytes.get(..sid_length) else {
        return false;
    };

    let mut local_service = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut local_service_length = local_service.len() as u32;
    // SAFETY: local_service is writable for its declared length and no domain SID is needed.
    if unsafe {
        CreateWellKnownSid(
            WinLocalServiceSid,
            None,
            Some(PSID(local_service.as_mut_ptr().cast())),
            &mut local_service_length,
        )
    }
    .is_err()
    {
        return false;
    }
    let local_service_length = local_service_length as usize;
    local_service
        .get(..local_service_length)
        .is_some_and(|expected| expected == user_sid)
}

/// Copies a NUL-terminated UTF-16 string only after bounding its in-buffer pointer.
fn bounded_config_string(storage: &[usize], pointer: *mut u16) -> Option<String> {
    crate::readiness::config_strings::bounded_config_string(
        storage,
        size_of::<QUERY_SERVICE_CONFIGW>(),
        pointer,
        crate::readiness::config_strings::ConfigStringKind::Required,
    )
}

/// Accepts documented NULL-as-empty only for optional dependency/group fields.
fn bounded_optional_config_string(storage: &[usize], pointer: *mut u16) -> Option<String> {
    crate::readiness::config_strings::bounded_config_string(
        storage,
        size_of::<QUERY_SERVICE_CONFIGW>(),
        pointer,
        crate::readiness::config_strings::ConfigStringKind::OptionalEmpty,
    )
}

/// Accepts only the fixed endpoint command identifying the current executable file.
fn service_binary_matches_current_process(command_line: &str) -> bool {
    let Some(path) = exact_endpoint_service_binary_path(command_line) else {
        return false;
    };
    let Ok(current_path) = std::env::current_exe() else {
        return false;
    };
    let Ok(configured) = File::open(path) else {
        return false;
    };
    let Ok(current) = File::open(current_path) else {
        return false;
    };
    same_file(&configured, &current)
}

/// Binds current-process file identity to the pinned fixed enrolled service image.
fn current_process_is_fixed_service() -> bool {
    let Ok(current_path) = std::env::current_exe() else {
        return false;
    };
    let Ok(current) = File::open(current_path) else {
        return false;
    };
    let Ok(expected) = File::open(crate::local_trust::LOCAL_SERVICE_BINARY) else {
        return false;
    };
    same_file(&current, &expected)
}

/// Compares stable volume/file-index identity instead of path spelling or case.
fn same_file(left: &File, right: &File) -> bool {
    let Some(left) = file_identity(left) else {
        return false;
    };
    let Some(right) = file_identity(right) else {
        return false;
    };
    left.dwVolumeSerialNumber == right.dwVolumeSerialNumber
        && left.nFileIndexHigh == right.nFileIndexHigh
        && left.nFileIndexLow == right.nFileIndexLow
}

/// Reads identity fields from one live file handle without exposing the handle.
fn file_identity(file: &File) -> Option<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: File owns a valid handle and information is exact writable storage.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information) }
        .ok()?;
    Some(information)
}

/// Converts an OS string to one NUL-terminated UTF-16 buffer.
fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

/// Reconstructs a private SC_HANDLE only for one service query.
fn service_handle(handle: &ServiceHandle) -> SC_HANDLE {
    SC_HANDLE(handle.copied() as *mut c_void)
}
