// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! C ABI for the direct N-API client; opaque leases retain every verified handle.
use std::ffi::c_void;
/// Verifies fixed local enrollment and retains the complete trusted runtime.
///
/// Returns null before transport readiness on any incomplete or invalid evidence.
/// The native client must release a successful opaque lease exactly once using
/// `openrdx_local_trust_close`; it cannot supply a path or trust policy.
#[unsafe(no_mangle)]
pub extern "C" fn openrdx_local_trust_open() -> *mut c_void {
    #[cfg(windows)]
    {
        let Ok(lease) = super::windows::verify_runtime_lease() else {
            return std::ptr::null_mut();
        };
        if crate::service_identity_access::prepare_current_manager_identity_queries(&lease).is_err()
        {
            return std::ptr::null_mut();
        }
        Box::into_raw(Box::new(lease)).cast()
    }
    #[cfg(not(windows))]
    {
        std::ptr::null_mut()
    }
}
/// Releases the runtime lease owned by a direct native client connection.
///
/// # Safety
/// `lease` must be null or an unreleased successful return from
/// `openrdx_local_trust_open`; ownership transfers to this function exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openrdx_local_trust_close(lease: *mut c_void) {
    #[cfg(windows)]
    {
        if !lease.is_null() {
            drop(unsafe { Box::from_raw(lease.cast::<super::windows::RuntimeLease>()) });
        }
    }
    #[cfg(not(windows))]
    {
        let _ = lease;
    }
}

/// Proves the service-specific SID is enabled in the exact server primary token.
/// Returns one only for the fixed OpenRDX service SID, never a supplied SID.
#[unsafe(no_mangle)]
pub extern "C" fn openrdx_local_trust_service_sid(process_id: u32) -> u8 {
    #[cfg(windows)]
    {
        u8::from(super::windows::service_sid_enabled(process_id).unwrap_or(false))
    }
    #[cfg(not(windows))]
    {
        let _ = process_id;
        0
    }
}
