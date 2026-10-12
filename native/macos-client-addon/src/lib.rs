// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed local enrollment adapter for the handle-owning macOS N-API client.
#![deny(unsafe_op_in_unsafe_fn)]
use std::{path::Path, sync::Mutex};

// Shared retained-file verification can consume thousands of descriptors. Keep
// concurrent UI status and connection attempts within one process budget.
static VERIFICATION_LOCK: Mutex<()> = Mutex::new(());

/// Validate protected fixed enrollment, app inventory and helper byte identity.
/// No caller-supplied path or hash influences this policy.
fn verified_hashes() -> Result<(String, String), rdx_local_trust::TrustError> {
    let _guard = VERIFICATION_LOCK
        .lock()
        .map_err(|_| rdx_local_trust::TrustError("verification lock unavailable".into()))?;
    let inventory = rdx_local_trust::verify_enrollment(
        Path::new(rdx_local_trust::MACOS_ENROLLMENT_PATH),
        "macos",
    )?;
    ensure_process_descriptor_budget(rdx_local_trust::runtime_handle_requirement(&inventory)?)?;
    rdx_local_trust::verify_protected_runtime(
        Path::new("/Applications/OpenRDXManager.app"),
        &inventory,
    )?;
    let helper = inventory
        .files
        .iter()
        .find(|file| file.path == "Contents/Library/LaunchServices/openrdx-hardware")
        .ok_or_else(|| rdx_local_trust::TrustError("missing enrolled helper".into()))?;
    rdx_local_trust::verify_protected_file(
        Path::new("/Library/PrivilegedHelperTools/openrdx-hardware"),
        &helper.sha256,
        helper.size,
    )?;
    Ok((inventory.helper_cd_hash, inventory.manager_cd_hash))
}

/// Copy exactly one verified canonical helper cdhash to a caller-owned 41-byte buffer.
///
/// # Safety
/// `output` and `manager_output` must each reference at least `capacity` writable bytes. The
/// native addon supplies a retained stack array, never a JavaScript address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rdx_macos_client_verified_hashes(
    output: *mut u8,
    manager_output: *mut u8,
    capacity: usize,
) -> bool {
    if output.is_null() || manager_output.is_null() || capacity != 41 {
        return false;
    }
    // No panic may unwind across the native FFI boundary.
    let Ok(Ok((hash, manager_hash))) = std::panic::catch_unwind(verified_hashes) else {
        return false;
    };
    if hash.len() != 40 || manager_hash.len() != 40 {
        return false;
    }
    // SAFETY: fixed capacity and non-null are established above; caller owns
    // the complete writable output array for this synchronous operation.
    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), output, 40);
        *output.add(40) = 0;
        std::ptr::copy_nonoverlapping(manager_hash.as_ptr(), manager_output, 40);
        *manager_output.add(40) = 0;
    }
    true
}

/// Raise only this app process soft descriptor limit within its existing hard limit.
/// Full runtime verification retains files and directories until all identities
/// have been rechecked. No host-global setting or privileged write is involved.
fn ensure_process_descriptor_budget(required: usize) -> Result<(), rdx_local_trust::TrustError> {
    let required = libc::rlim_t::try_from(required).map_err(|_| {
        rdx_local_trust::TrustError("descriptor budget exceeds native limit".into())
    })?;
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the scalar limit output points to initialized owned storage.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0
        || required > limits.rlim_max
    {
        return Err(rdx_local_trust::TrustError(
            "descriptor budget unavailable".into(),
        ));
    }
    if limits.rlim_cur < required {
        limits.rlim_cur = required;
        // SAFETY: the preserved hard limit and bounded new soft limit are valid;
        // setrlimit affects only the calling process, never machine policy.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
            return Err(rdx_local_trust::TrustError(
                "descriptor budget unavailable".into(),
            ));
        }
    }
    Ok(())
}

/// Verify exact root-protected signed runtime snapshot; caller must authenticate
/// the Apple/team app seal both before and after this check. This establishes
/// filesystem protection and content stability, never local enrollment or code
/// authority by itself. It accepts no JavaScript paths, hashes or policy input.
#[unsafe(no_mangle)]
pub extern "C" fn rdx_macos_client_verify_signed_runtime() -> bool {
    std::panic::catch_unwind(|| {
        let _guard = VERIFICATION_LOCK
            .lock()
            .map_err(|_| rdx_local_trust::TrustError("verification lock unavailable".into()))?;
        #[cfg(target_os = "macos")]
        {
            rdx_local_trust::verify_protected_signed_macos_runtime()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(rdx_local_trust::TrustError(
                "macOS protected runtime required".into(),
            ))
        }
    })
    .is_ok_and(|result| result.is_ok())
}
