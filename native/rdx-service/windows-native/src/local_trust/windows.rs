// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! No-follow, nonreplaceable handle leases for the fixed local runtime.
use super::{
    LOCAL_ENROLLMENT_ROOT, LOCAL_RUNTIME_ROOT, RuntimeAce, RuntimeAclEvidence, validate_runtime_acl,
};
use crate::NativeError;
use crate::installer::diagnostics::{InstallStage as Stage, diagnostic};
use rdx_local_trust::{MAX_INVENTORY_BYTES, RuntimeInventory, parse_inventory, verify_runtime};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{GENERIC_READ, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::core::{PCWSTR, PWSTR};

const DIRECTORY_SDDL: &str =
    "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;LS)(A;OICI;FRFX;;;BU)";
const FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;LS)(A;;FRFX;;;BU)";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

struct Allocation(*mut std::ffi::c_void);
impl Drop for Allocation {
    /// Releases only Windows LocalAlloc outputs owned by this wrapper.
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
    }
}
/// Complete runtime and enrollment stay pinned through the caller's authentication.
pub(crate) struct RuntimeLease {
    _files: Vec<File>,
    _inventory: RuntimeInventory,
}

/// Converts one bounded system-produced SID; input always belongs to its live descriptor.
fn sid_text(sid: PSID) -> Result<String, NativeError> {
    let mut output = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut output) }.map_err(|_| NativeError::AccessDenied)?;
    let output = Allocation(output.0.cast());
    unsafe { PWSTR(output.0.cast()).to_string() }.map_err(|_| NativeError::AccessDenied)
}
/// Reads every owner and ACE from the retained handle, rejecting unsupported ACE forms.
pub(crate) fn evidence(file: &File) -> Result<RuntimeAclEvidence, NativeError> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    let mut dacl = std::ptr::null_mut();
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(|_| NativeError::AccessDenied)?;
    let allocation = Allocation(descriptor.0);
    let descriptor = PSECURITY_DESCRIPTOR(allocation.0);
    let mut control = 0u16;
    let mut revision = 0;
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(|_| NativeError::AccessDenied)?;
    if dacl.is_null()
        || !unsafe { IsValidAcl(dacl).as_bool() }
        || !unsafe { IsValidSid(owner).as_bool() }
    {
        return Err(NativeError::AccessDenied);
    }
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if length == 0 || length > 65536 {
        return Err(NativeError::ResourceLimit);
    }
    let base = allocation.0 as usize;
    let end = base.checked_add(length).ok_or(NativeError::ResourceLimit)?;
    let header = unsafe { &*dacl };
    if header.AceCount > 128 {
        return Err(NativeError::ResourceLimit);
    }
    let mut entries = Vec::new();
    for index in 0..header.AceCount {
        let mut pointer = std::ptr::null_mut();
        unsafe { GetAce(dacl, index as u32, &mut pointer) }
            .map_err(|_| NativeError::AccessDenied)?;
        let address = pointer as usize;
        if address < base
            || address
                .checked_add(size_of::<ACCESS_ALLOWED_ACE>())
                .is_none_or(|v| v > end)
        {
            return Err(NativeError::AccessDenied);
        }
        let ace = unsafe { &*pointer.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != 0 && ace.Header.AceType != 1 {
            return Err(NativeError::AccessDenied);
        }
        let ace_end = address
            .checked_add(ace.Header.AceSize as usize)
            .ok_or(NativeError::ResourceLimit)?;
        if ace_end > end || (ace.Header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(NativeError::AccessDenied);
        }
        let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
        if !unsafe { IsValidSid(sid).as_bool() }
            || sid.0 as usize + unsafe { GetLengthSid(sid) } as usize > ace_end
        {
            return Err(NativeError::AccessDenied);
        }
        entries.push(RuntimeAce {
            sid: sid_text(sid)?,
            mask: ace.Mask,
            flags: ace.Header.AceFlags,
            allowed: ace.Header.AceType == 0,
        });
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(|_| NativeError::AccessDenied)?;
    Ok(RuntimeAclEvidence {
        owner: sid_text(owner)?,
        protected: control & SE_DACL_PROTECTED.0 != 0,
        reparse: info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0,
        directory: info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
        links: info.nNumberOfLinks,
        entries,
    })
}
/// Opens the exact spelling without following reparse points, denying replacement/write races.
pub(crate) fn open(path: &Path, mutate_acl: bool) -> Result<File, NativeError> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let desired = GENERIC_READ.0
        | READ_CONTROL.0
        | if mutate_acl {
            WRITE_DAC.0 | WRITE_OWNER.0
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    let info = evidence(&file)?;
    if info.reparse || (!info.directory && info.links != 1) {
        return Err(NativeError::AccessDenied);
    }
    Ok(file)
}
/// Pins each ancestor and denies policy-changing rights to unprivileged principals.
pub(super) fn ancestors(path: &Path) -> Result<Vec<File>, NativeError> {
    let mut paths: Vec<_> = path.ancestors().skip(1).collect();
    paths.reverse();
    let mut files = Vec::new();
    for parent in paths {
        let file = open(parent, false)?;
        let info = evidence(&file)?;
        if !matches!(info.owner.as_str(), "S-1-5-18" | "S-1-5-32-544")
            && info.owner != TRUSTED_INSTALLER
        {
            return Err(NativeError::AccessDenied);
        }
        for ace in &info.entries {
            if ace.allowed
                && ace.flags & 8 == 0
                && ace.mask
                    & (0x00010000 | 0x00040000 | 0x00080000 | 0x40 | 0x40000000 | 0x10000000)
                    != 0
                && !matches!(ace.sid.as_str(), "S-1-5-18" | "S-1-5-32-544")
                && ace.sid != TRUSTED_INSTALLER
            {
                return Err(NativeError::AccessDenied);
            }
        }
        files.push(file);
    }
    Ok(files)
}
/// Applies the sole fixed ACL after proving an existing object has privileged-only mutation.
pub(crate) fn protect(path: &Path, administrator_sid: &str) -> Result<(), NativeError> {
    let file = open(path, true)?;
    let info = evidence(&file)?;
    if !matches!(info.owner.as_str(), "S-1-5-18" | "S-1-5-32-544")
        && info.owner != TRUSTED_INSTALLER
        && info.owner != administrator_sid
    {
        return Err(NativeError::AccessDenied);
    }
    for ace in &info.entries {
        if ace.allowed
            && ace.flags & 8 == 0
            && ace.mask & (0x000d0156 | 0x40000000 | 0x10000000) != 0
            && !matches!(ace.sid.as_str(), "S-1-5-18" | "S-1-5-32-544")
            && ace.sid != TRUSTED_INSTALLER
            && ace.sid != administrator_sid
        {
            return Err(NativeError::AccessDenied);
        }
    }
    let sddl: Vec<u16> = if info.directory {
        DIRECTORY_SDDL
    } else {
        FILE_SDDL
    }
    .encode_utf16()
    .chain([0])
    .collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let sd = Allocation(sd.0);
    let mut owner = PSID::default();
    unsafe {
        GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR(sd.0), &mut owner, &mut false.into())
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let mut present = false.into();
    let mut defaulted = false.into();
    let mut dacl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(sd.0),
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    unsafe {
        SetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            Some(owner),
            None,
            Some(dacl),
            None,
        )
    }
    .ok()
    .map_err(|_| NativeError::AccessDenied)?;
    validate_runtime_acl(&evidence(&file)?)
}
/// Pins the exact installed tree, including inventory-excluded files, with bounded traversal.
fn pin_tree(root: &Path, files: &mut Vec<File>) -> Result<(), NativeError> {
    let file = open(root, false)?;
    validate_runtime_acl(&evidence(&file)?)?;
    files.push(file);
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).map_err(|_| NativeError::AccessDenied)? {
            let entry = entry.map_err(|_| NativeError::AccessDenied)?;
            count += 1;
            if count > 40000 {
                return Err(NativeError::ResourceLimit);
            }
            let file = open(&entry.path(), false)?;
            let info = evidence(&file)?;
            validate_runtime_acl(&info)?;
            if info.directory {
                pending.push(entry.path());
            }
            files.push(file);
        }
    }
    Ok(())
}
/// Verifies administrator enrollment first and content while every object remains pinned.
pub(crate) fn verify_runtime_lease() -> Result<RuntimeLease, NativeError> {
    let runtime = Path::new(LOCAL_RUNTIME_ROOT);
    let enrollment = Path::new(LOCAL_ENROLLMENT_ROOT).join("runtime.json");
    let mut files = ancestors(runtime)?;
    files.extend(ancestors(&enrollment)?);
    let mut file = open(&enrollment, false)?;
    validate_runtime_acl(&evidence(&file)?)?;
    if file
        .metadata()
        .map_err(|_| NativeError::AccessDenied)?
        .len()
        > MAX_INVENTORY_BYTES as u64
    {
        return Err(NativeError::ResourceLimit);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| NativeError::AccessDenied)?;
    let inventory = parse_inventory(&bytes, "windows").map_err(|_| NativeError::AccessDenied)?;
    files.push(file);
    pin_tree(runtime, &mut files)?;
    verify_runtime(runtime, &inventory).map_err(|_| NativeError::AccessDenied)?;
    for file in &files {
        if evidence(file)?.reparse {
            return Err(NativeError::AccessDenied);
        }
    }
    Ok(RuntimeLease {
        _files: files,
        _inventory: inventory,
    })
}
/// Validates protected parent ownership before a first installation creates its root.
pub(crate) fn verify_fresh_install_root() -> Result<(), NativeError> {
    let _parents = ancestors(Path::new(LOCAL_RUNTIME_ROOT))?;
    if Path::new(LOCAL_RUNTIME_ROOT).exists() {
        let _empty = super::bootstrap::validate_empty_root(Path::new(LOCAL_RUNTIME_ROOT))?;
    }
    for path in [r"C:\ProgramData\OpenRDXManager", LOCAL_ENROLLMENT_ROOT] {
        let path = Path::new(path);
        if path.exists() {
            validate_runtime_acl(&evidence(&open(path, false)?)?)?;
        }
    }
    Ok(())
}
/// Elevated repair/removal proves durable administrator history and object ownership,
/// allowing missing or corrupted content without granting runtime authentication.
pub(crate) fn verify_owned_runtime_lease() -> Result<RuntimeLease, NativeError> {
    let runtime = Path::new(LOCAL_RUNTIME_ROOT);
    let history = Path::new(LOCAL_ENROLLMENT_ROOT).join("history.json");
    let mut files = ancestors(runtime)?;
    files.extend(ancestors(&history)?);
    verify_owned_objects(runtime, &history, files)
}
/// Checks a retained historical record and every remaining runtime object, without hashes.
pub(super) fn verify_owned_objects(
    runtime: &Path,
    history: &Path,
    mut files: Vec<File>,
) -> Result<RuntimeLease, NativeError> {
    let mut file = open(history, false)?;
    validate_runtime_acl(&evidence(&file)?)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_INVENTORY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| NativeError::AccessDenied)?;
    let inventory = parse_inventory(&bytes, "windows").map_err(|_| NativeError::AccessDenied)?;
    files.push(file);
    if runtime.exists() {
        super::bootstrap::pin_interrupted_tree(runtime, &mut files)?;
    }
    Ok(RuntimeLease {
        _files: files,
        _inventory: inventory,
    })
}
/// Pins the protected packaged inventory for elevated setup before enrollment publication.
pub(crate) fn verify_packaged_runtime_lease() -> Result<RuntimeLease, NativeError> {
    let runtime = Path::new(LOCAL_RUNTIME_ROOT);
    let mut files = ancestors(runtime)?;
    pin_tree(runtime, &mut files)?;
    let mut bytes = Vec::new();
    open(&runtime.join("resources/local-trust/runtime.json"), false)?
        .take(MAX_INVENTORY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| NativeError::AccessDenied)?;
    let inventory = parse_inventory(&bytes, "windows").map_err(|_| NativeError::AccessDenied)?;
    verify_runtime(runtime, &inventory).map_err(|_| NativeError::AccessDenied)?;
    Ok(RuntimeLease {
        _files: files,
        _inventory: inventory,
    })
}
/// Candidate holds the complete protected runtime until publication finishes.
pub(crate) struct PreparedEnrollment {
    _pins: Vec<File>,
    bytes: Vec<u8>,
}
/// Atomically creates only a private test root beneath pinned protected Program Files.
#[cfg(test)]
pub(crate) fn token_verifier_fixture_root() -> Result<(PathBuf, Vec<File>), NativeError> {
    // SAFETY: GUID generation requires no initialization or caller-owned pointers.
    let id =
        unsafe { windows::Win32::System::Com::CoCreateGuid() }.map_err(|_| NativeError::Other)?;
    let root = PathBuf::from(r"C:\Program Files")
        .join(format!("OpenRDXTokenVerifier-{:032x}", id.to_u128()));
    let pins = ancestors(&root)?;
    create_protected_directory(&root)?;
    Ok((root, pins))
}
/// Creates machine policy directories with the final privileged owner at creation.
pub(super) fn create_protected_directory(path: &Path) -> Result<(), NativeError> {
    let text: Vec<u16> = DIRECTORY_SDDL.encode_utf16().chain([0]).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let _allocation = Allocation(descriptor.0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&attributes)) }
        .map_err(|_| NativeError::AccessDenied)
}
/// Protects final installer files and prepares complete enrollment without publishing it.
fn prepare_runtime_files(
    runtime: &Path,
    administrator_sid: &str,
) -> Result<(Vec<File>, Vec<u8>), NativeError> {
    let _parents = diagnostic(Stage::RuntimeAncestors, ancestors(runtime))?;
    let mut pending = vec![runtime.to_path_buf()];
    let mut count = 0;
    while let Some(path) = pending.pop() {
        let info = diagnostic(Stage::RuntimeOpen, (|| evidence(&open(&path, false)?))())?;
        diagnostic(Stage::RuntimeProtection, protect(&path, administrator_sid))?;
        if info.directory {
            for entry in diagnostic(
                Stage::RuntimeOpen,
                std::fs::read_dir(&path).map_err(|_| NativeError::AccessDenied),
            )? {
                count += 1;
                if count > 40000 {
                    return Err(NativeError::ResourceLimit);
                }
                pending.push(
                    diagnostic(
                        Stage::RuntimeOpen,
                        entry.map_err(|_| NativeError::AccessDenied),
                    )?
                    .path(),
                );
            }
        }
    }
    let mut pins = diagnostic(Stage::RuntimeAncestors, ancestors(runtime))?;
    diagnostic(Stage::RuntimePinning, pin_tree(runtime, &mut pins))?;
    let mut inventory = diagnostic(
        Stage::RuntimeManifest,
        (|| {
            let packaged = runtime.join("resources/local-trust/runtime.json");
            let packaged_file = open(&packaged, false)?;
            let mut bytes = Vec::new();
            packaged_file
                .take(MAX_INVENTORY_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| NativeError::AccessDenied)?;
            parse_inventory(&bytes, "windows").map_err(|_| NativeError::AccessDenied)
        })(),
    )?;
    diagnostic(
        Stage::RuntimeInventory,
        verify_runtime(runtime, &inventory).map_err(|_| NativeError::AccessDenied),
    )?;
    // NSIS emits these fixed files after packaging. Administrator-approved setup
    // pins their final generated contents rather than leaving runtime exclusions.
    let bytes = diagnostic(
        Stage::RuntimeArtifacts,
        (|| {
            for name in ["Uninstall OpenRDXManager.exe", "uninstallerIcon.ico"] {
                let path = runtime.join(name);
                if path.exists() && !inventory.files.iter().any(|file| file.path == name) {
                    use sha2::{Digest, Sha256};
                    let mut file = open(&path, false)?;
                    let size = file
                        .metadata()
                        .map_err(|_| NativeError::AccessDenied)?
                        .len();
                    let mut hasher = Sha256::new();
                    let mut buffer = [0u8; 65536];
                    loop {
                        let read = file
                            .read(&mut buffer)
                            .map_err(|_| NativeError::AccessDenied)?;
                        if read == 0 {
                            break;
                        }
                        hasher.update(&buffer[..read]);
                    }
                    inventory.files.push(rdx_local_trust::RuntimeFile {
                        path: name.to_owned(),
                        size,
                        sha256: format!("{:x}", hasher.finalize()),
                    });
                }
            }
            let bytes = serde_json::to_vec(&inventory).map_err(|_| NativeError::AccessDenied)?;
            let inventory =
                parse_inventory(&bytes, "windows").map_err(|_| NativeError::AccessDenied)?;
            verify_runtime(runtime, &inventory).map_err(|_| NativeError::AccessDenied)?;
            Ok(bytes)
        })(),
    )?;
    Ok((pins, bytes))
}
/// Prepares the sole fixed runtime and records privileged installation history.
pub(crate) fn prepare_runtime(administrator_sid: &str) -> Result<PreparedEnrollment, NativeError> {
    let (pins, bytes) = prepare_runtime_files(Path::new(LOCAL_RUNTIME_ROOT), administrator_sid)?;
    diagnostic(
        Stage::RuntimeHistory,
        (|| {
            let parent = PathBuf::from(r"C:\ProgramData\OpenRDXManager");
            if !parent.exists() {
                create_protected_directory(&parent)?;
            } else {
                validate_runtime_acl(&evidence(&open(&parent, false)?)?)?;
            }
            protect(&parent, administrator_sid)?;
            let enrollment = Path::new(LOCAL_ENROLLMENT_ROOT);
            if !enrollment.exists() {
                create_protected_directory(enrollment)?;
            } else {
                validate_runtime_acl(&evidence(&open(enrollment, false)?)?)?;
            }
            protect(enrollment, administrator_sid)?;
            write_policy_atomic(&bytes, "history", administrator_sid)?;
            Ok(())
        })(),
    )?;
    Ok(PreparedEnrollment { _pins: pins, bytes })
}
/// Publishes the prepared generation only after service and device policy checks succeed.
pub(crate) fn commit_enrollment(
    candidate: &PreparedEnrollment,
    administrator_sid: &str,
) -> Result<(), NativeError> {
    write_policy_atomic(&candidate.bytes, "runtime", administrator_sid)?;
    let _verified = verify_runtime_lease()?;
    Ok(())
}
/// Persists only the fixed device permission journal with atomic protected creation.
pub(crate) fn write_device_policy(bytes: &[u8]) -> Result<(), NativeError> {
    if bytes.len() > MAX_INVENTORY_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    write_policy_atomic(bytes, "device-access", "")
}
/// Returns stable retained NTFS identity for cleanup, never following a replacement.
fn file_identity(file: &File) -> Result<(u32, u32, u32), NativeError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(|_| NativeError::AccessDenied)?;
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}
/// Writes a fixed policy atomically with its final security descriptor at creation.
/// Failed writes clean only the exact retained identity; stale protected temporaries
/// are safely recoverable while reparses, hardlinks and foreign policies are refused.
pub(super) fn write_policy_atomic(
    bytes: &[u8],
    name: &str,
    _administrator_sid: &str,
) -> Result<(), NativeError> {
    if !matches!(name, "runtime" | "history" | "device-access") {
        return Err(NativeError::InvalidRequest);
    }
    let enrollment = Path::new(LOCAL_ENROLLMENT_ROOT);
    write_pinned_policy_at(enrollment, bytes, name)
}
/// Pins the protected parent namespace while permitting atomic child-file replacement.
/// A read-only lease on the enrollment directory itself blocks MoveFileExW. Its
/// canonical ACL is checked by the writer; the retained parent prevents directory
/// replacement without broadening any runtime or history-file sharing flags.
/// Rename API: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
fn write_pinned_policy_at(enrollment: &Path, bytes: &[u8], name: &str) -> Result<(), NativeError> {
    let _parents = ancestors(enrollment)?;
    write_policy_at(enrollment, bytes, name)
}
/// Atomic writer shared with native filesystem fixtures; production selects its fixed parent.
pub(super) fn write_policy_at(
    enrollment: &Path,
    bytes: &[u8],
    name: &str,
) -> Result<(), NativeError> {
    let directory = open(enrollment, false)?;
    validate_runtime_acl(&evidence(&directory)?)?;
    let directory_identity = file_identity(&directory)?;
    drop(directory);
    let destination = enrollment.join(format!("{name}.json"));
    if destination.exists() {
        validate_runtime_acl(&evidence(&open(&destination, false)?)?)?;
    }
    let temporary = enrollment.join(format!("{name}.new"));
    if temporary.exists() {
        let stale = open(&temporary, false)?;
        validate_runtime_acl(&evidence(&stale)?)?;
        drop(stale);
        std::fs::remove_file(&temporary).map_err(|_| NativeError::AccessDenied)?;
    }
    let descriptor: Vec<u16> = FILE_SDDL.encode_utf16().chain([0]).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(descriptor.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let _allocation = Allocation(sd.0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let from: Vec<u16> = temporary.as_os_str().encode_wide().chain([0]).collect();
    let to: Vec<u16> = destination.as_os_str().encode_wide().chain([0]).collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(from.as_ptr()),
            GENERIC_READ.0 | windows::Win32::Foundation::GENERIC_WRITE.0 | 0x20000,
            FILE_SHARE_READ,
            Some(&attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let mut output = unsafe { File::from_raw_handle(handle.0) };
    let identity = file_identity(&output)?;
    let result = (|| {
        validate_runtime_acl(&evidence(&output)?)?;
        output
            .write_all(bytes)
            .map_err(|_| NativeError::AccessDenied)?;
        output.sync_all().map_err(|_| NativeError::AccessDenied)
    })();
    drop(output);
    let result = result.and_then(|()| {
        // Reprove the canonical directory and retained namespace identity immediately
        // before publication, then close its conflicting read lease for the rename.
        let directory = open(enrollment, false)?;
        validate_runtime_acl(&evidence(&directory)?)?;
        if file_identity(&directory)? != directory_identity {
            return Err(NativeError::AccessDenied);
        }
        drop(directory);
        unsafe {
            MoveFileExW(
                PCWSTR(from.as_ptr()),
                PCWSTR(to.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| NativeError::AccessDenied)
    });
    if result.is_err() && temporary.exists() {
        let owned = open(&temporary, false)?;
        validate_runtime_acl(&evidence(&owned)?)?;
        if file_identity(&owned)? != identity {
            return Err(NativeError::AccessDenied);
        }
        drop(owned);
        std::fs::remove_file(&temporary).map_err(|_| NativeError::AccessDenied)?;
    }
    result
}
/// Revokes only an exact protected enrollment, preserving all user data.
pub(crate) fn remove_enrollment() -> Result<(), NativeError> {
    let path = Path::new(LOCAL_ENROLLMENT_ROOT).join("runtime.json");
    if path.exists() {
        let file = open(&path, false)?;
        validate_runtime_acl(&evidence(&file)?)?;
        drop(file);
        std::fs::remove_file(path).map_err(|_| NativeError::AccessDenied)?;
    }
    Ok(())
}

/// Verifies the enabled service SID in a bounded token-group allocation.
pub(crate) fn service_sid_enabled(process_id: u32) -> Result<bool, NativeError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
        .map_err(|_| NativeError::AccessDenied)?;
    let mut token = HANDLE::default();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    let _ = unsafe { CloseHandle(process) };
    opened.map_err(|_| NativeError::AccessDenied)?;
    let mut storage = vec![0usize; 8192];
    let mut returned = 0;
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            Some(storage.as_mut_ptr().cast()),
            (storage.len() * size_of::<usize>()) as u32,
            &mut returned,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    read.map_err(|_| NativeError::AccessDenied)?;
    let base = storage.as_ptr() as usize;
    let end = base
        .checked_add(returned as usize)
        .ok_or(NativeError::ResourceLimit)?;
    if returned as usize > storage.len() * size_of::<usize>()
        || (returned as usize) < size_of::<TOKEN_GROUPS>()
    {
        return Err(NativeError::AccessDenied);
    }
    let groups = unsafe { &*storage.as_ptr().cast::<TOKEN_GROUPS>() };
    let first = groups.Groups.as_ptr();
    let count = groups.GroupCount as usize;
    if count > 1024
        || (first as usize)
            .checked_add(count * size_of::<SID_AND_ATTRIBUTES>())
            .is_none_or(|v| v > end)
    {
        return Err(NativeError::AccessDenied);
    }
    let account: Vec<u16> = "NT SERVICE\\OpenRDXHardwareService"
        .encode_utf16()
        .chain([0])
        .collect();
    let mut expected = vec![0usize; 32];
    let mut sid_size = (expected.len() * size_of::<usize>()) as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut usage = SID_NAME_USE::default();
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(expected.as_mut_ptr().cast())),
            &mut sid_size,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_size,
            &mut usage,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    for index in 0..count {
        let group = unsafe { &*first.add(index) };
        let address = group.Sid.0 as usize;
        if address < base || address.checked_add(8).is_none_or(|v| v > end) {
            return Err(NativeError::AccessDenied);
        }
        let length = 8 + unsafe { *(address as *const u8).add(1) } as usize * 4;
        if address.checked_add(length).is_none_or(|v| v > end) {
            return Err(NativeError::AccessDenied);
        }
        if unsafe { EqualSid(group.Sid, PSID(expected.as_ptr().cast_mut().cast())).is_ok() }
            && group.Attributes & 0x00000004 != 0
            && group.Attributes & 0x00000010 == 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Reads the fixture creator's actual principal without assuming tests run as SYSTEM.
#[cfg(test)]
pub(super) fn test_administrator_sid() -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.unwrap();
    let mut storage = vec![0usize; 512];
    let mut returned = 0;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            (storage.len() * size_of::<usize>()) as u32,
            &mut returned,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    result.unwrap();
    assert!(returned as usize <= storage.len() * size_of::<usize>());
    assert!(returned as usize >= size_of::<TOKEN_USER>());
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    sid_text(user.User.Sid).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// Creates a unique disposable directory without accepting production trust overrides.
    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "openrdx-native-acl-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }
    /// A real ordinary test process never proves the fixed enabled service-specific SID.
    #[test]
    fn native_service_sid_rejects_an_unrelated_process_token() {
        // Windows may not resolve a service SID until its service is registered.
        // Either absent mapping or a token without the enabled SID must deny.
        assert!(!matches!(service_sid_enabled(std::process::id()), Ok(true)));
        assert!(service_sid_enabled(0).is_err());
    }
    /// Applies real protected owner/DACL policy and confirms a pinned object cannot be replaced.
    #[test]
    fn native_acl_and_retained_identity_block_replacement() {
        let root = fixture();
        let path = root.join("runtime-file");
        std::fs::write(&path, b"approved").unwrap();
        protect(&path, &test_administrator_sid()).unwrap();
        let file = open(&path, false).unwrap();
        validate_runtime_acl(&evidence(&file).unwrap()).unwrap();
        assert!(std::fs::rename(&path, root.join("replacement")).is_err());
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        drop(file);
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Rejects a real second hardlink even when the object's owner/DACL are canonical.
    #[test]
    fn native_hardlink_rejected_before_policy_admission() {
        let root = fixture();
        let path = root.join("runtime-file");
        std::fs::write(&path, b"approved").unwrap();
        protect(&path, &test_administrator_sid()).unwrap();
        std::fs::hard_link(&path, root.join("alias")).unwrap();
        assert!(open(&path, false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Applies an actual broad Users grant to test complete native DACL rejection.
    fn broaden_acl(path: &Path) {
        let file = open(path, true).unwrap();
        let text: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)"
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .unwrap();
        let _allocation = Allocation(descriptor.0);
        let mut dacl = std::ptr::null_mut();
        let mut present = false.into();
        let mut defaulted = false.into();
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            .unwrap();
        unsafe {
            SetSecurityInfo(
                HANDLE(file.as_raw_handle()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        }
        .ok()
        .unwrap();
    }
    /// Corrupt bytes are administrator-repairable while content authentication still denies.
    #[test]
    fn owned_history_allows_corrupt_repair_but_never_runtime_authentication() {
        let fixture = fixture();
        let runtime = fixture.join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        protect(&runtime, &test_administrator_sid()).unwrap();
        let path = runtime.join("component");
        std::fs::write(&path, b"corrupted").unwrap();
        protect(&path, &test_administrator_sid()).unwrap();
        let inventory = RuntimeInventory {
            schema_version: 1,
            platform: "windows".into(),
            files: vec![rdx_local_trust::RuntimeFile {
                path: "component".into(),
                size: 8,
                sha256: "0".repeat(64),
            }],
            links: vec![],
            manager_cd_hash: "".into(),
            helper_cd_hash: "".into(),
        };
        let history = fixture.join("history.json");
        std::fs::write(&history, serde_json::to_vec(&inventory).unwrap()).unwrap();
        protect(&history, &test_administrator_sid()).unwrap();
        assert!(verify_runtime(&runtime, &inventory).is_err());
        drop(verify_owned_objects(&runtime, &history, vec![]).unwrap());
        std::fs::hard_link(&path, runtime.join("alias")).unwrap();
        assert!(verify_owned_objects(&runtime, &history, vec![]).is_err());
        std::fs::remove_file(runtime.join("alias")).unwrap();
        let redirect = runtime.join("redirect");
        std::os::windows::fs::symlink_dir(&fixture, &redirect).unwrap();
        assert!(verify_owned_objects(&runtime, &history, vec![]).is_err());
        std::fs::remove_dir(&redirect).unwrap();
        broaden_acl(&path);
        assert!(verify_owned_objects(&runtime, &history, vec![]).is_err());
        std::fs::remove_dir_all(fixture).unwrap();
    }
    /// A failed atomic rename removes only its created temporary, and retry succeeds.
    #[test]
    fn failed_atomic_policy_publication_has_no_stale_retry_blocker() {
        let root = fixture();
        protect(&root, &test_administrator_sid()).unwrap();
        let destination = root.join("runtime.json");
        std::fs::create_dir(&destination).unwrap();
        protect(&destination, &test_administrator_sid()).unwrap();
        assert!(write_policy_at(&root, b"policy", "runtime").is_err());
        assert!(!root.join("runtime.new").exists());
        std::fs::remove_dir(&destination).unwrap();
        write_policy_at(&root, b"policy", "runtime").unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"policy");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod installation_tests;
