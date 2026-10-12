// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Administrator-selected incoming source and durable first-install intent.

use super::windows::{
    ancestors, create_protected_directory, evidence, open, protect, write_policy_at,
};
use super::{
    LOCAL_ENROLLMENT_ROOT, LOCAL_RUNTIME_ROOT, validate_interrupted_runtime_acl,
    validate_runtime_acl,
};
use crate::NativeError;
#[cfg(test)]
use rdx_local_trust::RuntimeInventory;
use rdx_local_trust::{MAX_INVENTORY_BYTES, parse_inventory};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

struct IncomingSource {
    _files: Vec<File>,
    bytes: Vec<u8>,
    #[cfg(test)]
    inventory: RuntimeInventory,
}
/// Pins the fixed sibling source, its protected parent and the current executable.
/// NSIS 3.12 creates the source parent atomically with a privileged owner; setup
/// removes its Everyone DELETE_CHILD grant before extracting these source files.
fn incoming_source(executable: &Path) -> Result<IncomingSource, NativeError> {
    if executable.file_name() != Some(std::ffi::OsStr::new("openrdx-local-install.exe")) {
        return Err(NativeError::AccessDenied);
    }
    let parent = executable.parent().ok_or(NativeError::AccessDenied)?;
    let mut retained = ancestors(executable)?;
    let directory = open(parent, false)?;
    validate_runtime_acl(&evidence(&directory)?)?;
    let mut provisioner = open(executable, false)?;
    validate_interrupted_runtime_acl(&evidence(&provisioner)?)?;
    let mut manifest = open(&parent.join("pending-runtime.json"), false)?;
    validate_interrupted_runtime_acl(&evidence(&manifest)?)?;
    let mut bytes = Vec::new();
    (&mut manifest)
        .take(MAX_INVENTORY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| NativeError::AccessDenied)?;
    let inventory = parse_inventory(&bytes, "windows").map_err(|_| NativeError::AccessDenied)?;
    let expected = inventory
        .files
        .iter()
        .find(|file| file.path == "resources/native/windows/openrdx-local-install.exe")
        .ok_or(NativeError::AccessDenied)?;
    let size = provisioner
        .metadata()
        .map_err(|_| NativeError::AccessDenied)?
        .len();
    if size != expected.size || size > 64 * 1024 * 1024 {
        return Err(NativeError::AccessDenied);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = provisioner
            .read(&mut buffer)
            .map_err(|_| NativeError::AccessDenied)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if format!("{:x}", hasher.finalize()) != expected.sha256 {
        return Err(NativeError::AccessDenied);
    }
    retained.extend([directory, provisioner, manifest]);
    Ok(IncomingSource {
        _files: retained,
        bytes,
        #[cfg(test)]
        inventory,
    })
}
/// Persists administrator history without creating an IPC enrollment or service start grant.
fn persist_intent(policy: &Path, bytes: &[u8]) -> Result<(), NativeError> {
    write_policy_at(policy, bytes, "history")
}
/// Retains a canonical empty directory only; no unrecorded payload may be adopted.
pub(super) fn validate_empty_root(path: &Path) -> Result<File, NativeError> {
    let file = open(path, false)?;
    let info = evidence(&file)?;
    validate_runtime_acl(&info)?;
    if !info.directory
        || std::fs::read_dir(path)
            .map_err(|_| NativeError::AccessDenied)?
            .next()
            .is_some()
    {
        return Err(NativeError::AccessDenied);
    }
    Ok(file)
}
/// Creates the fixed first-install intent and protected empty root before any payload write.
/// Caller already proved the fixed SCM name is absent; no path or identity is supplied.
pub(crate) fn prepare_first_install() -> Result<(), NativeError> {
    super::windows::verify_fresh_install_root()?;
    let executable = std::env::current_exe().map_err(|_| NativeError::AccessDenied)?;
    let incoming = incoming_source(&executable)?;
    let runtime = Path::new(LOCAL_RUNTIME_ROOT);
    let existing_root = if runtime.exists() {
        Some(validate_empty_root(runtime)?)
    } else {
        None
    };
    for directory in [r"C:\ProgramData\OpenRDXManager", LOCAL_ENROLLMENT_ROOT] {
        let path = Path::new(directory);
        if path.exists() {
            validate_runtime_acl(&evidence(&open(path, false)?)?)?;
        } else {
            create_protected_directory(path)?;
        }
    }
    super::windows::remove_enrollment()?;
    persist_intent(Path::new(LOCAL_ENROLLMENT_ROOT), &incoming.bytes)?;
    if existing_root.is_none() {
        create_protected_directory(runtime)?;
    }
    Ok(())
}
/// Normalizes only exact privileged inherited policy after protected history proof.
/// This elevated recovery path never authenticates IPC or ignores an unknown DACL.
pub(crate) fn pin_interrupted_tree(
    runtime: &Path,
    files: &mut Vec<File>,
) -> Result<(), NativeError> {
    let mut pending = vec![runtime.to_path_buf()];
    let mut count = 0;
    while let Some(path) = pending.pop() {
        count += 1;
        if count > 40000 {
            return Err(NativeError::ResourceLimit);
        }
        let file = open(&path, false)?;
        let info = evidence(&file)?;
        validate_interrupted_runtime_acl(&info)?;
        drop(file);
        if !info.protected {
            protect(&path, "")?;
        }
        let file = open(&path, false)?;
        validate_runtime_acl(&evidence(&file)?)?;
        if info.directory {
            for entry in std::fs::read_dir(&path).map_err(|_| NativeError::AccessDenied)? {
                pending.push(entry.map_err(|_| NativeError::AccessDenied)?.path());
            }
        }
        files.push(file);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::windows::{create_protected_directory, protect, verify_owned_objects};
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// Uses disposable paths only; production bootstrap has no path arguments.
    fn fixture() -> PathBuf {
        let parent = std::env::var_os("OPENRDX_TEST_UNTRUSTED_TEMP_PARENT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\Temp"));
        let root = parent.join(format!(
            "openrdx-bootstrap-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        create_protected_directory(&root).unwrap();
        root
    }
    /// Creates an exact incoming self-pin with canonical protected NTFS policy.
    fn source(root: &std::path::Path) -> PathBuf {
        let exe = root.join("openrdx-local-install.exe");
        std::fs::write(&exe, b"incoming-provisioner").unwrap();
        protect(&exe, "S-1-5-18").unwrap();
        let bytes = serde_json::to_vec(&rdx_local_trust::RuntimeInventory {
            schema_version: 1,
            platform: "windows".into(),
            links: vec![],
            manager_cd_hash: "".into(),
            helper_cd_hash: "".into(),
            files: vec![rdx_local_trust::RuntimeFile {
                path: "resources/native/windows/openrdx-local-install.exe".into(),
                size: 20,
                sha256: format!("{:x}", Sha256::digest(b"incoming-provisioner")),
            }],
        })
        .unwrap();
        let manifest = root.join("pending-runtime.json");
        std::fs::write(&manifest, bytes).unwrap();
        protect(&manifest, "S-1-5-18").unwrap();
        exe
    }
    /// A canonical incoming child beneath ordinary-user-writable temp is not authority.
    #[test]
    fn incoming_source_rejects_user_writable_temp_ancestor() {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SetFileSecurityW,
        };
        use windows::core::PCWSTR;
        let root = fixture();
        let incoming = root.join("incoming");
        create_protected_directory(&incoming).unwrap();
        let exe = source(&incoming);
        // An explicit test-only parent lets the VM prove rejection of the real
        // interactive user-owned Temp before adding any synthetic broad ACE.
        if std::env::var_os("OPENRDX_TEST_UNTRUSTED_TEMP_PARENT").is_some() {
            assert!(incoming_source(&exe).is_err());
        }
        let sddl: Vec<u16> = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .unwrap();
        let path: Vec<u16> = root.as_os_str().encode_wide().chain([0]).collect();
        assert!(
            unsafe {
                SetFileSecurityW(
                    PCWSTR(path.as_ptr()),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor,
                )
            }
            .as_bool()
        );
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        assert!(incoming_source(&exe).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Only a previously protected empty fixed root can precede the durable intent.
    #[test]
    fn fresh_intent_refuses_nonempty_and_unprotected_preexisting_roots() {
        let root = fixture();
        drop(validate_empty_root(&root).unwrap());
        std::fs::write(root.join("foreign-payload"), b"foreign").unwrap();
        assert!(validate_empty_root(&root).is_err());
        std::fs::remove_file(root.join("foreign-payload")).unwrap();
        let inherited = root.join("inherited-empty");
        std::fs::create_dir(&inherited).unwrap();
        assert!(validate_empty_root(&inherited).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Exercises the exact NSIS SetFileSecurityW call against retained native evidence.
    #[test]
    fn nsis_source_hardening_produces_exact_native_dacl() {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
        };
        use windows::core::PCWSTR;
        let root = fixture();
        let sddl: Vec<u16> =
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;LS)(A;OICI;FRFX;;;BU)"
                .encode_utf16()
                .chain([0])
                .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .unwrap();
        let path: Vec<u16> = root.as_os_str().encode_wide().chain([0]).collect();
        assert!(
            unsafe {
                SetFileSecurityW(
                    PCWSTR(path.as_ptr()),
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor,
                )
            }
            .as_bool()
        );
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        let exe = source(&root);
        drop(incoming_source(&exe).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Interrupted extraction is owned after intent, but cannot pass content authentication.
    #[test]
    fn incoming_intent_survives_partial_extraction_without_enrollment() {
        let root = fixture();
        let exe = source(&root);
        let incoming = incoming_source(&exe).unwrap();
        let policy = root.join("policy");
        create_protected_directory(&policy).unwrap();
        persist_intent(&policy, &incoming.bytes).unwrap();
        assert!(!policy.join("runtime.json").exists());
        let runtime = root.join("runtime");
        create_protected_directory(&runtime).unwrap();
        // NSIS children initially inherit the protected parent's exact read-only grants.
        std::fs::write(runtime.join("partial"), b"incomplete").unwrap();
        assert!(rdx_local_trust::verify_runtime(&runtime, &incoming.inventory).is_err());
        drop(verify_owned_objects(&runtime, &policy.join("history.json"), vec![]).unwrap());
        drop(incoming);
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Source bytes must match the strict inventory's fixed provisioner entry.
    #[test]
    fn incoming_source_rejects_changed_bytes_and_hardlinks() {
        let root = fixture();
        let exe = source(&root);
        std::fs::write(&exe, b"changed").unwrap();
        assert!(incoming_source(&exe).is_err());
        std::fs::write(&exe, b"incoming-provisioner").unwrap();
        std::fs::hard_link(&exe, root.join("alias")).unwrap();
        assert!(incoming_source(&exe).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Foreign source parents and historical records cannot be normalized into owned state.
    #[test]
    fn incoming_source_and_history_require_protected_parent_acl() {
        let root = fixture();
        let exe = source(&root);
        let file = super::super::windows::open(&root, false).unwrap();
        assert!(
            super::super::validate_runtime_acl(&super::super::windows::evidence(&file).unwrap())
                .is_ok()
        );
        drop(file);
        let foreign = root.join("unprotected-source");
        std::fs::create_dir(&foreign).unwrap();
        let foreign_exe = source(&foreign);
        assert!(incoming_source(&foreign_exe).is_err());
        let runtime = root.join("runtime");
        create_protected_directory(&runtime).unwrap();
        // An unprotected historical file inherits read-only ACEs but is not an
        // administrator-published intent and cannot authorize any normalization.
        std::fs::copy(root.join("pending-runtime.json"), root.join("history.json")).unwrap();
        assert!(verify_owned_objects(&runtime, &root.join("history.json"), vec![]).is_err());
        std::fs::remove_file(root.join("history.json")).unwrap();
        // A foreign manifest name never supplies authority; only the fixed sibling is read.
        std::fs::rename(
            root.join("pending-runtime.json"),
            root.join("arbitrary.json"),
        )
        .unwrap();
        assert!(incoming_source(&exe).is_err());
        assert!(verify_owned_objects(&runtime, &root.join("history.json"), vec![]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
