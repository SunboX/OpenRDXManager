// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed protected ACL for the Windows drive-letter preference registry root.

const REGISTRY_KEY: &str = r"HKEY_LOCAL_MACHINE\SOFTWARE\OpenRDXManager\DriveLetters";
const LOCAL_SYSTEM_FULL: u32 = 0x000f_003f;
const ADMINISTRATORS_FULL: u32 = 0x000f_003f;
const LOCAL_SERVICE_PARENT: u32 = 0x0002_000f;
const LOCAL_SERVICE_CHILD: u32 = 0x0003_000f;

/// Fixed principals admitted by the preference registry root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryDaclPrincipal {
    /// LocalSystem retains full administrative ownership.
    LocalSystem,
    /// Built-in administrators own and fully administer the tree.
    Administrators,
    /// The LocalService daemon may manage only values and serial child keys.
    LocalService,
}

/// One exact canonical registry ACE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryDaclEntry {
    /// Fixed semantic principal.
    pub principal: RegistryDaclPrincipal,
    /// Exact registry/standard access mask.
    pub access_mask: u32,
    /// Whether the ACE propagates to child serial keys.
    pub container_inherit: bool,
    /// Whether this ACE applies only to child serial keys.
    pub inherit_only: bool,
}

const REGISTRY_DACL_ENTRIES: [RegistryDaclEntry; 4] = [
    RegistryDaclEntry {
        principal: RegistryDaclPrincipal::LocalSystem,
        access_mask: LOCAL_SYSTEM_FULL,
        container_inherit: true,
        inherit_only: false,
    },
    RegistryDaclEntry {
        principal: RegistryDaclPrincipal::Administrators,
        access_mask: ADMINISTRATORS_FULL,
        container_inherit: true,
        inherit_only: false,
    },
    RegistryDaclEntry {
        principal: RegistryDaclPrincipal::LocalService,
        access_mask: LOCAL_SERVICE_PARENT,
        container_inherit: false,
        inherit_only: false,
    },
    RegistryDaclEntry {
        principal: RegistryDaclPrincipal::LocalService,
        access_mask: LOCAL_SERVICE_CHILD,
        container_inherit: true,
        inherit_only: true,
    },
];

/// Portable contract for the fixed protected registry root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryDaclContract {
    /// Fixed HKLM key; callers cannot supply a path.
    pub key: &'static str,
    /// Required owner.
    pub owner: RegistryDaclPrincipal,
    /// Required primary group.
    pub group: RegistryDaclPrincipal,
    /// Whether inheritance is disabled.
    pub protected: bool,
    /// Exact canonical ordered ACEs.
    pub entries: &'static [RegistryDaclEntry],
}

/// Returns the exact least-privilege registry ACL contract.
#[must_use]
pub const fn drive_letter_registry_dacl_contract() -> RegistryDaclContract {
    RegistryDaclContract {
        key: REGISTRY_KEY,
        owner: RegistryDaclPrincipal::Administrators,
        group: RegistryDaclPrincipal::LocalSystem,
        protected: true,
        entries: &REGISTRY_DACL_ENTRIES,
    }
}

/// Records whether provisioning created the exact root in this transaction.
#[cfg(windows)]
pub(crate) struct RegistryProvisioning {
    created: bool,
    committed: bool,
}

#[cfg(windows)]
impl RegistryProvisioning {
    /// Prevents rollback after the service DACL and registry ACL are both verified.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

#[cfg(windows)]
impl Drop for RegistryProvisioning {
    /// Removes only a newly created empty root when the paired service change fails.
    fn drop(&mut self) {
        if self.created && !self.committed {
            windows_impl::rollback_new_empty_root();
        }
    }
}

/// Atomically creates the exact key with its final descriptor, or accepts an exact existing key.
#[cfg(windows)]
pub(crate) fn provision_registry_acl() -> Result<RegistryProvisioning, crate::NativeError> {
    windows_impl::provision()
}

/// Verifies the complete owner, protected inheritance state, and canonical DACL.
#[cfg(windows)]
pub(crate) fn registry_acl_ready() -> bool {
    windows_impl::verify().is_ok()
}

#[cfg(windows)]
mod windows_impl {
    use super::RegistryProvisioning;
    use crate::NativeError;
    use std::mem::size_of;
    use windows::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HLOCAL, LocalFree,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    };
    use windows::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC, WRITE_OWNER};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE,
        KEY_SET_VALUE, REG_CREATED_NEW_KEY, REG_OPENED_EXISTING_KEY, REG_OPTION_NON_VOLATILE,
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegGetKeySecurity, RegOpenKeyExW,
        RegQueryInfoKeyW,
    };
    use windows::core::{BOOL, PCWSTR, PWSTR};

    const RELATIVE_KEY: &str = r"SOFTWARE\OpenRDXManager\DriveLetters";
    const EXPECTED_SDDL: &str = "O:BAG:SYD:P(A;CI;0x000f003f;;;SY)(A;CI;0x000f003f;;;BA)(A;;0x0002000f;;;LS)(A;CIIO;0x0003000f;;;LS)";
    const MAX_DESCRIPTOR_BYTES: usize = 65_536;

    struct RegistryKey(HKEY);

    impl Drop for RegistryKey {
        /// Closes one exact registry key handle.
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns a successful registry handle.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    struct LocalDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalDescriptor {
        /// Releases one LocalAlloc-owned security descriptor.
        fn drop(&mut self) {
            // SAFETY: conversion returned this allocation and it is released once.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }

    struct LocalString(PWSTR);

    impl Drop for LocalString {
        /// Releases one LocalAlloc-owned converted security string.
        fn drop(&mut self) {
            // SAFETY: conversion returned this allocation and it is released once.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
        }
    }

    /// Creates with the final descriptor in the same kernel call or verifies exact existing state.
    pub(super) fn provision() -> Result<RegistryProvisioning, NativeError> {
        let descriptor = expected_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: BOOL(0),
        };
        let path = wide(RELATIVE_KEY);
        let mut raw = HKEY::default();
        let mut disposition = Default::default();
        // SAFETY: fixed path and final descriptor are live for this synchronous create/open.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE
                    | KEY_SET_VALUE
                    | KEY_CREATE_SUB_KEY
                    | KEY_ENUMERATE_SUB_KEYS
                    | windows::Win32::System::Registry::REG_SAM_FLAGS(READ_CONTROL.0)
                    | windows::Win32::System::Registry::REG_SAM_FLAGS(WRITE_DAC.0)
                    | windows::Win32::System::Registry::REG_SAM_FLAGS(WRITE_OWNER.0),
                Some(&attributes),
                &mut raw,
                Some(&mut disposition),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(map_status(status));
        }
        let key = RegistryKey(raw);
        let created = if disposition == REG_CREATED_NEW_KEY {
            true
        } else if disposition == REG_OPENED_EXISTING_KEY {
            false
        } else {
            return Err(NativeError::Other);
        };
        verify_key(&key)?;
        Ok(RegistryProvisioning {
            created,
            committed: false,
        })
    }

    /// Opens query-only and validates the exact complete security contract.
    pub(super) fn verify() -> Result<(), NativeError> {
        let path = wide(RELATIVE_KEY);
        let mut raw = HKEY::default();
        // SAFETY: fixed path is NUL-terminated and output storage is writable.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                windows::Win32::System::Registry::REG_SAM_FLAGS(READ_CONTROL.0),
                &mut raw,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(map_status(status));
        }
        verify_key(&RegistryKey(raw))
    }

    /// Deletes only the new empty final key; child creation makes rollback fail closed.
    pub(super) fn rollback_new_empty_root() {
        let path = wide(RELATIVE_KEY);
        let mut raw = HKEY::default();
        // SAFETY: fixed path is NUL-terminated and output storage is writable.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                &mut raw,
            )
        };
        if status != ERROR_SUCCESS {
            return;
        }
        let key = RegistryKey(raw);
        let mut subkey_count = 0_u32;
        let mut value_count = 0_u32;
        // SAFETY: the retained key handle is live and both count outputs are writable.
        let status = unsafe {
            RegQueryInfoKeyW(
                key.0,
                None,
                None,
                None,
                Some(&mut subkey_count),
                None,
                None,
                Some(&mut value_count),
                None,
                None,
                None,
                None,
            )
        };
        drop(key);
        if status == ERROR_SUCCESS && subkey_count == 0 && value_count == 0 {
            // SAFETY: the path is fixed; emptiness was proved immediately before deletion.
            let _ = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(path.as_ptr())) };
        }
    }

    /// Compares normalized complete security descriptors generated by Windows itself.
    fn verify_key(key: &RegistryKey) -> Result<(), NativeError> {
        let observed = read_descriptor_sddl(key)?;
        let expected = expected_descriptor()?;
        if observed == canonical_sddl(expected.0)? {
            Ok(())
        } else {
            Err(NativeError::AccessDenied)
        }
    }

    /// Reads one bounded owner/group/DACL descriptor from the exact key.
    fn read_descriptor_sddl(key: &RegistryKey) -> Result<String, NativeError> {
        let information = security_information();
        let mut needed = 0_u32;
        // SAFETY: null descriptor with zero size is the documented sizing query.
        let status = unsafe { RegGetKeySecurity(key.0, information, None, &mut needed) };
        if status != ERROR_INSUFFICIENT_BUFFER
            || needed == 0
            || needed as usize > MAX_DESCRIPTOR_BYTES
        {
            return Err(map_status(status));
        }
        let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = storage.len() * size_of::<usize>();
        // SAFETY: aligned storage is writable for its exact bounded capacity.
        let status = unsafe {
            RegGetKeySecurity(
                key.0,
                information,
                Some(PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast())),
                &mut needed,
            )
        };
        if status != ERROR_SUCCESS || needed as usize > capacity {
            return Err(map_status(status));
        }
        canonical_sddl(PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast()))
    }

    /// Builds one LocalAlloc-owned descriptor from the immutable SDDL contract.
    fn expected_descriptor() -> Result<LocalDescriptor, NativeError> {
        let sddl = wide(EXPECTED_SDDL);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: SDDL is fixed/NUL-terminated and output receives one LocalAlloc allocation.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|_| NativeError::Other)?;
        Ok(LocalDescriptor(descriptor))
    }

    /// Converts a descriptor to Windows-canonical SDDL for exact semantic comparison.
    fn canonical_sddl(descriptor: PSECURITY_DESCRIPTOR) -> Result<String, NativeError> {
        let mut text = PWSTR::null();
        let mut length = 0_u32;
        // SAFETY: descriptor is live and outputs receive one LocalAlloc string and length.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                security_information(),
                &mut text,
                Some(&mut length),
            )
        }
        .map_err(|_| NativeError::Other)?;
        let text = LocalString(text);
        if text.0.is_null() || length == 0 || length > 4096 {
            return Err(NativeError::Other);
        }
        // SAFETY: successful conversion returned length live UTF-16 units.
        String::from_utf16(unsafe { std::slice::from_raw_parts(text.0.0, length as usize) })
            .map_err(|_| NativeError::Other)
    }

    /// Returns the exact fields included in readiness/provisioning comparison.
    fn security_information() -> OBJECT_SECURITY_INFORMATION {
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    }

    /// Encodes one fixed string as NUL-terminated UTF-16.
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Maps only stable access/not-found versus other status classes.
    fn map_status(status: windows::Win32::Foundation::WIN32_ERROR) -> NativeError {
        if status == windows::Win32::Foundation::ERROR_ACCESS_DENIED {
            NativeError::AccessDenied
        } else if status == ERROR_FILE_NOT_FOUND {
            NativeError::EvidenceIncomplete
        } else {
            NativeError::Other
        }
    }
}
