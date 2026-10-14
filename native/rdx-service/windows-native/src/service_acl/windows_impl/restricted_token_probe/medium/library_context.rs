// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only restricting-SID and fixed system-library DACL observations, not loader proof.
use super::*;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorLength,
    OWNER_SECURITY_INFORMATION, TokenHasRestrictions, TokenRestrictedSids,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, GetFileInformationByHandle, OPEN_EXISTING,
};
use windows::Win32::System::Memory::LocalSize;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

/// Reads every restricting SID within the bounded kernel buffer; returns presence only.
fn restricting_sids(token: &OwnedHandle) -> Result<bool, NativeError> {
    let buffer = TokenBuffer::read(token, TokenRestrictedSids)?;
    restricting_presence(&buffer)
}

/// Validates the complete bounded table before returning presence/absence; no raw SID escapes.
fn restricting_presence(buffer: &TokenBuffer) -> Result<bool, NativeError> {
    let entries = buffer
        .entries::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), buffer.header::<u32>()?)?;
    for entry in &entries {
        let _private_sid = buffer.sid(entry.Sid)?;
    }
    Ok(!entries.is_empty())
}

/// Emits only complete bounded SID-query facts and independently queried ever-filtered status.
fn token_fields(subject: &'static str, token: &OwnedHandle) -> Vec<String> {
    let restricted = restricting_sids(token);
    let filtered = scalar(token, TokenHasRestrictions);
    let fields = [
        ("restricted-sids-query-ok", restricted.is_ok()),
        (
            "restricted-sids-empty",
            restricted.as_ref().is_ok_and(|value| !*value),
        ),
        (
            "restricted-sids-present",
            restricted.as_ref().is_ok_and(|value| *value),
        ),
        ("has-restrictions-query-ok", filtered.is_ok()),
        (
            "has-restrictions",
            filtered.as_ref().is_ok_and(|value| *value != 0),
        ),
    ];
    fields
        .iter()
        .map(|(key, value)| format!("{subject}-{key}={value}"))
        .collect()
}

/// Resolves the architecture-correct system directory from the kernel API, never user environment.
fn system_directory() -> Result<PathBuf, NativeError> {
    let mut units = vec![0_u16; 32_768];
    // SAFETY: bounded initialized output; returned size is checked before UTF-16 conversion.
    let length = unsafe { GetSystemDirectoryW(Some(&mut units)) } as usize;
    if length == 0 || length >= units.len() {
        return Err(NativeError::Other);
    }
    let directory = PathBuf::from(OsString::from_wide(&units[..length]));
    if !directory.is_absolute() {
        return Err(NativeError::Other);
    }
    Ok(directory)
}

/// Owns one exact fixed system file; ordinary runtime trust policy remains unchanged.
struct Library(OwnedHandle);
impl Library {
    /// Pins only the selected fixed DLL with read-only query access; rejects reparse/directory objects.
    fn open(directory: &Path, basename: &'static str) -> Result<Self, NativeError> {
        let path = wide_null(directory.join(basename).as_os_str());
        // SAFETY: private kernel-derived absolute directory plus one compiled basename;
        // no writes, inherited handles, loader calls or caller-supplied destination.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                READ_CONTROL_MASK | FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(map_native_error)?;
        let owned = OwnedHandle(handle);
        let mut evidence = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: retained owned file handle and initialized writable evidence structure.
        unsafe { GetFileInformationByHandle(owned.0, &mut evidence) }.map_err(map_native_error)?;
        if evidence.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0)
            != 0
        {
            return Err(NativeError::Other);
        }
        // System DLLs legitimately have WinSxS hardlinks. This test-only reader
        // intentionally does not apply or change production runtime hardlink policy.
        Ok(Self(owned))
    }

    /// Queries owner/group/DACL by retained handle, then copies the bounded descriptor privately.
    fn descriptor(&self) -> Result<Descriptor, NativeError> {
        struct Allocation(PSECURITY_DESCRIPTOR);
        impl Drop for Allocation {
            /// Frees only this API allocation even on later validation failure.
            fn drop(&mut self) {
                if !self.0.0.is_null() {
                    // SAFETY: this pointer is owned exclusively from GetSecurityInfo.
                    let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
                }
            }
        }
        let mut allocation = Allocation(PSECURITY_DESCRIPTOR::default());
        // SAFETY: held file handle, read-only owner/group/DACL flags, writable allocation output.
        let status = unsafe {
            GetSecurityInfo(
                self.0.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut allocation.0),
            )
        };
        if status.0 != 0 || allocation.0.0.is_null() {
            return Err(NativeError::Other);
        }
        // SAFETY: the SDK allocation is LocalFree-compatible; actual allocation extent
        // bounds the later descriptor length/copy independently of embedded offsets.
        let allocation_size = unsafe { LocalSize(HLOCAL(allocation.0.0)) };
        if !(size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=MAX_PROBE_BYTES).contains(&allocation_size)
        {
            return Err(NativeError::Other);
        }
        // SAFETY: successful OS-owned descriptor allocation; length bounds checked before copying.
        let length = unsafe { GetSecurityDescriptorLength(allocation.0) } as usize;
        if !(size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=allocation_size).contains(&length) {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; length.div_ceil(size_of::<usize>())];
        // SAFETY: OS initialized descriptor fits the declared bounded aligned destination.
        unsafe {
            std::ptr::copy_nonoverlapping(
                allocation.0.0.cast::<u8>(),
                storage.as_mut_ptr().cast(),
                length,
            )
        };
        let descriptor = Descriptor { storage, length };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

/// Checks file READ/EXECUTE DACL rights using the same restricted token semantics, without mapping DLLs.
fn file_allowed(
    descriptor: &Descriptor,
    token: &OwnedHandle,
    execute: bool,
) -> Result<bool, NativeError> {
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    let desired = if execute {
        FILE_GENERIC_EXECUTE.0
    } else {
        FILE_GENERIC_READ.0
    };
    dacl_access(descriptor, token, desired, &mapping)
}

/// Observes only two explicit fixture imports; does not claim complete transitive/CRT coverage.
pub(super) fn observe(source: &OwnedHandle, derived: &OwnedHandle) {
    let mut fields = token_fields("source", source);
    fields.extend(token_fields("derived", derived));
    let directory = system_directory();
    fields.push(format!("system-directory-query-ok={}", directory.is_ok()));
    for (tag, basename) in [("kernel32", "kernel32.dll"), ("advapi32", "advapi32.dll")] {
        let library = directory
            .as_ref()
            .ok()
            .and_then(|directory| Library::open(directory, basename).ok());
        let descriptor = library
            .as_ref()
            .and_then(|library| library.descriptor().ok());
        fields.push(format!("{tag}-file-query-ok={}", library.is_some()));
        fields.push(format!(
            "{tag}-descriptor-query-ok={}",
            descriptor.is_some()
        ));
        for (subject, token) in [("source", source), ("derived", derived)] {
            for (access, execute) in [("read", false), ("execute", true)] {
                let result = descriptor
                    .as_ref()
                    .map(|descriptor| file_allowed(descriptor, token, execute));
                fields.push(format!(
                    "{subject}-{tag}-{access}-query-ok={}",
                    result.as_ref().is_some_and(|result| result.is_ok())
                ));
                fields.push(format!(
                    "{subject}-{tag}-{access}-allowed={}",
                    result
                        .as_ref()
                        .is_some_and(|result| result.as_ref().is_ok_and(|value| *value))
                ));
            }
        }
        // The exact opened file stays pinned until its final descriptor/access checks complete.
        drop(library);
    }
    println!("openrdx-token-library-context {}", fields.join(" "));
}

/// Missing/overflowing tables and invalid SID pointers cannot produce presence or absence evidence.
#[test]
fn restricting_metadata_failures_are_unknown() {
    let mut storage = vec![0_usize; 8];
    let length = storage.len() * size_of::<usize>();
    let mut buffer = TokenBuffer {
        storage: storage.clone(),
        length,
    };
    assert!(restricting_presence(&buffer) == Ok(false));
    // SAFETY: aligned initialized storage contains the fixed DWORD count prefix.
    unsafe { storage.as_mut_ptr().cast::<u32>().write(u32::MAX) };
    buffer.storage = storage;
    assert!(restricting_presence(&buffer).is_err());
    // SAFETY: reset the table count to one within the same bounded initialized storage.
    unsafe { buffer.storage.as_mut_ptr().cast::<u32>().write(1) };
    // The zeroed first SID pointer is outside the allocation, so it is never dereferenced.
    assert!(restricting_presence(&buffer).is_err());
    buffer.length = 0;
    assert!(restricting_presence(&buffer).is_err());
}
