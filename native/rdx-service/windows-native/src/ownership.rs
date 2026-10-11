// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protected process-global Windows hardware mutation ownership.

use crate::NativeError;

#[cfg(windows)]
use std::{marker::PhantomData, rc::Rc};

const OWNERSHIP_NAME: &str = r"Global\OpenRDXHardwareMutation";
const CLIENT_ACCESS_MASK: u32 = 0x0010_0001;

/// Immutable protected named-mutex contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareOwnershipContract {
    /// Fixed machine-global kernel object name.
    pub name: &'static str,
    /// Exact principals granted synchronization and release rights.
    pub principals: [&'static str; 3],
    /// Exact `SYNCHRONIZE | MUTEX_MODIFY_STATE` client mask.
    pub client_access_mask: u32,
    /// Whether an already-existing object makes service initialization fail.
    pub first_creator_must_be_service: bool,
    /// Whether acquisition always returns immediately.
    pub nonblocking: bool,
    /// Whether a direct client must hold a fully elevated process token.
    pub direct_requires_elevation: bool,
}

/// Retained protected namespace object created only by the service.
#[derive(Debug)]
pub struct HardwareOwnershipNamespace {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
}

/// One process-global exclusive hardware execution lease.
#[derive(Debug)]
pub struct HardwareOwnershipGuard {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
    // A Win32 mutex must be released by the thread that acquired it.
    #[cfg(windows)]
    _thread_affinity: PhantomData<Rc<()>>,
}

/// Returns the immutable Windows process-global ownership contract.
#[must_use]
pub const fn hardware_ownership_contract() -> HardwareOwnershipContract {
    HardwareOwnershipContract {
        name: OWNERSHIP_NAME,
        principals: ["local-system", "administrators", "local-service"],
        client_access_mask: CLIENT_ACCESS_MASK,
        first_creator_must_be_service: true,
        nonblocking: true,
        direct_requires_elevation: true,
    }
}

/// Creates the protected namespace and rejects pre-existing name ownership.
///
/// # Errors
///
/// Returns a sanitized failure when this process is not the first protected
/// service creator or the kernel object cannot be created exactly.
pub fn initialize_hardware_ownership_namespace() -> Result<HardwareOwnershipNamespace, NativeError>
{
    #[cfg(windows)]
    {
        windows_impl::initialize()
    }
    #[cfg(not(windows))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Opens and acquires the service-created protected mutex without waiting.
///
/// # Errors
///
/// Returns [`NativeError::Busy`] when another service or CLI owns execution,
/// and fails closed if the namespace is absent or access is not authorized.
pub fn try_acquire_hardware_ownership() -> Result<HardwareOwnershipGuard, NativeError> {
    #[cfg(windows)]
    {
        windows_impl::try_acquire()
    }
    #[cfg(not(windows))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Returns whether this exact Windows process has a fully elevated token.
///
/// This query does not grant access. Direct mutation additionally requires a
/// successfully acquired service-created ownership mutex and exact candidate
/// identity revalidation by the native backend.
#[must_use]
pub fn current_process_is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows_impl::current_process_is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
impl Drop for HardwareOwnershipNamespace {
    /// Closes the namespace handle after connection admission stops.
    fn drop(&mut self) {
        // SAFETY: this guard owns the handle exactly once.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(windows)]
impl Drop for HardwareOwnershipGuard {
    /// Releases and closes exactly this acquired mutex handle.
    fn drop(&mut self) {
        // SAFETY: successful construction proved current-thread ownership.
        let _ = unsafe { windows::Win32::System::Threading::ReleaseMutex(self.handle) };
        // SAFETY: this guard owns the handle exactly once.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::mem::size_of;

    use windows::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, GetLastError, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION,
        TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{
        CreateMutexExW, GetCurrentProcess, OpenMutexW, OpenProcessToken,
        SYNCHRONIZATION_ACCESS_RIGHTS, WaitForSingleObject,
    };
    use windows::core::PCWSTR;

    use super::{
        CLIENT_ACCESS_MASK, HardwareOwnershipGuard, HardwareOwnershipNamespace, OWNERSHIP_NAME,
    };
    use crate::NativeError;

    const PROTECTED_SDDL: &str = "D:P(A;;0x00100001;;;SY)(A;;0x00100001;;;BA)(A;;0x00100001;;;LS)";

    struct LocalDescriptor(PSECURITY_DESCRIPTOR);

    struct OwnedToken(windows::Win32::Foundation::HANDLE);

    impl Drop for LocalDescriptor {
        /// Releases one LocalAlloc-owned security descriptor exactly once.
        fn drop(&mut self) {
            // SAFETY: the conversion API returned this LocalAlloc-owned pointer.
            let _ = unsafe {
                windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    self.0.0,
                )))
            };
        }
    }

    impl Drop for OwnedToken {
        /// Closes one query-only process token handle exactly once.
        fn drop(&mut self) {
            // SAFETY: successful construction transferred one owned handle.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
        }
    }

    /// Proves that the current process token is fully elevated.
    pub(super) fn current_process_is_elevated() -> bool {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        // SAFETY: the pseudo-process handle is valid, access is query-only, and
        // token is writable output transferred immediately into RAII.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }
        let token = OwnedToken(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0_u32;
        // SAFETY: elevation is exact writable TOKEN_ELEVATION storage.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        }
        .is_ok()
            && returned as usize >= size_of::<TOKEN_ELEVATION>()
            && elevation.TokenIsElevated != 0
    }

    /// Creates the first protected machine-global mutex object.
    pub(super) fn initialize() -> Result<HardwareOwnershipNamespace, NativeError> {
        let sddl = wide(PROTECTED_SDDL);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: input is NUL-terminated and output receives one owned descriptor.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        let descriptor = LocalDescriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        let name = wide(OWNERSHIP_NAME);
        // SAFETY: attributes and name remain live through this creation call.
        let handle = unsafe {
            CreateMutexExW(
                Some(&attributes),
                PCWSTR(name.as_ptr()),
                0,
                CLIENT_ACCESS_MASK,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        // SAFETY: last error is read immediately after the creation call.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: this branch still owns the returned existing-object handle.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            return Err(NativeError::AccessDenied);
        }
        Ok(HardwareOwnershipNamespace { handle })
    }

    /// Opens the service-created mutex and acquires it with a zero timeout.
    pub(super) fn try_acquire() -> Result<HardwareOwnershipGuard, NativeError> {
        let name = wide(OWNERSHIP_NAME);
        // SAFETY: the fixed name is NUL-terminated and no inheritance is requested.
        let handle = unsafe {
            OpenMutexW(
                SYNCHRONIZATION_ACCESS_RIGHTS(CLIENT_ACCESS_MASK),
                false,
                PCWSTR(name.as_ptr()),
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        // SAFETY: handle is a live mutex and zero makes the wait nonblocking.
        match unsafe { WaitForSingleObject(handle, 0) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(HardwareOwnershipGuard {
                handle,
                _thread_affinity: std::marker::PhantomData,
            }),
            WAIT_TIMEOUT => {
                // SAFETY: acquisition failed, so only the handle is owned.
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                Err(NativeError::Busy)
            }
            _ => {
                // SAFETY: acquisition failed, so only the handle is owned.
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                Err(NativeError::Other)
            }
        }
    }

    /// Converts one fixed ASCII policy string into NUL-terminated UTF-16.
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::hardware_ownership_contract;

    /// The Windows ownership object is global, protected, and nonblocking.
    #[test]
    fn production_contract_is_fixed_and_protected() {
        let contract = hardware_ownership_contract();

        assert_eq!(contract.name, r"Global\OpenRDXHardwareMutation");
        assert_eq!(
            contract.principals,
            ["local-system", "administrators", "local-service"]
        );
        assert_eq!(contract.client_access_mask, 0x0010_0001);
        assert!(contract.first_creator_must_be_service);
        assert!(contract.nonblocking);
        assert!(contract.direct_requires_elevation);
    }
}
