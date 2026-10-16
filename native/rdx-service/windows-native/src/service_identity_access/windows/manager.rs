// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-service query access to the currently verified Manager process only.

use super::OwnObjects;
use crate::NativeError;
use crate::service_identity_access::{
    FixedServiceSid, fixed_service_lookup_capacity_valid, grant_manager_query_access,
};
use windows::Win32::Security::{GetLengthSid, IsValidSid, LookupAccountNameW, PSID, SID_NAME_USE};
use windows::core::{PCWSTR, PWSTR};

/// Derives only NT SERVICE\\OpenRDXHardwareService from the local account database.
pub(super) fn fixed_service_sid() -> Result<FixedServiceSid, NativeError> {
    let account: Vec<u16> = "NT SERVICE\\OpenRDXHardwareService"
        .encode_utf16()
        .chain([0])
        .collect();
    let mut storage = [0_u32; 17];
    let mut sid_size = std::mem::size_of_val(&storage) as u32;
    let mut domain = [0_u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut usage = SID_NAME_USE::default();
    // SAFETY: the account is compiled and local; both output allocations are
    // aligned, initialized and bounded. No supplied SID/name/path enters lookup.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(storage.as_mut_ptr().cast())),
            &mut sid_size,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_size,
            &mut usage,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let pointer = PSID(storage.as_mut_ptr().cast());
    // LookupAccountNameW may retain cbSid's input capacity on success (observed
    // 68 for this valid 32-byte SID). Only IsValidSid + GetLengthSid establish
    // its actual extent; the returned capacity must still fit our allocation.
    if !fixed_service_lookup_capacity_valid(sid_size, std::mem::size_of_val(&storage))
        || domain_size as usize >= domain.len()
        // SAFETY: lookup succeeded inside the complete bounded SID allocation.
        || !unsafe { IsValidSid(pointer).as_bool() }
        || unsafe { GetLengthSid(pointer) } != 32
    {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: the valid 32-byte SID is inside live aligned lookup storage.
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), 32) };
    // Service SIDs have S-1-5-80 plus exactly five service-name hash components.
    if bytes[..12] != [1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0] {
        return Err(NativeError::AccessDenied);
    }
    Ok(FixedServiceSid(
        bytes.try_into().map_err(|_| NativeError::AccessDenied)?,
    ))
}

/// Proves the fixed Manager role before any idempotent current-process grant.
/// The retained runtime lease outlives transport use; no Manager token is opened here.
pub(crate) fn prepare_current_manager_identity_queries(
    lease: &crate::local_trust::windows::RuntimeLease,
) -> Result<(), NativeError> {
    lease.verify_current_manager_process()?;
    grant_manager_query_access(&OwnObjects::process_only(), &fixed_service_sid()?)
}
