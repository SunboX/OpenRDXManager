// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Actual owned suspended-child security observations, not MIC/loader/authorization proof.
use super::desktop_context::{Descriptor, dacl_access};
use super::*;
#[path = "object_acl.rs"]
mod object_acl;
use windows::Win32::Security::{
    GENERIC_MAPPING, GetKernelObjectSecurity, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_EXECUTE,
    TOKEN_OWNER, TOKEN_READ, TOKEN_READ_CONTROL, TOKEN_WRITE, TokenDefaultDacl, TokenOwner,
};
use windows::Win32::System::Threading::{
    PROCESS_ALL_ACCESS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, THREAD_ALL_ACCESS,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SYNCHRONIZE,
};

/// A fixed standard security-query right, never used to mutate objects.
const READ_CONTROL_MASK: u32 = 0x0002_0000;

/// Queries only bounded owner/group/DACL from an existing retained owned kernel handle.
/// Access-token object descriptors explicitly use this documented API.
/// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
pub(super) fn descriptor(handle: HANDLE) -> Result<Descriptor, NativeError> {
    let mut needed = 0;
    // SAFETY: retained owned handle, sizing output only; no SACL/privilege request.
    let sizing = unsafe { GetKernelObjectSecurity(handle, 1 | 2 | 4, None, 0, &mut needed) };
    if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
        || !(size_of::<windows::Win32::Security::SECURITY_DESCRIPTOR_RELATIVE>()..=MAX_PROBE_BYTES)
            .contains(&(needed as usize))
    {
        return Err(NativeError::Other);
    }
    let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let capacity = storage.len() * size_of::<usize>();
    // SAFETY: initialized aligned bounded storage, live kernel handle, read-only flags.
    unsafe {
        GetKernelObjectSecurity(
            handle,
            1 | 2 | 4,
            Some(windows::Win32::Security::PSECURITY_DESCRIPTOR(
                storage.as_mut_ptr().cast(),
            )),
            capacity as u32,
            &mut needed,
        )
    }
    .map_err(map_native_error)?;
    if !(size_of::<windows::Win32::Security::SECURITY_DESCRIPTOR_RELATIVE>()..=capacity)
        .contains(&(needed as usize))
    {
        return Err(NativeError::Other);
    }
    let observed = Descriptor {
        storage,
        length: needed as usize,
    };
    observed.validate()?;
    Ok(observed)
}

/// Bounds a default-DACL pointer privately; null is valid, unsupported encodings remain unknown.
fn default_dacl(buffer: &TokenBuffer) -> Result<bool, NativeError> {
    let header = buffer.header::<TOKEN_DEFAULT_DACL>()?;
    if header.DefaultDacl.is_null() {
        return Ok(true);
    }
    let start = buffer.storage.as_ptr() as usize;
    let offset = (header.DefaultDacl as usize)
        .checked_sub(start)
        .filter(|offset| {
            *offset >= size_of::<TOKEN_DEFAULT_DACL>()
                && *offset % 4 == 0
                && offset
                    .checked_add(8)
                    .is_some_and(|end| end <= buffer.length)
        })
        .ok_or(NativeError::Other)?;
    // SAFETY: initialized bounded token query bytes; ACL parser checks all extents privately.
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.storage.as_ptr().cast::<u8>(), buffer.length) };
    object_acl::validate_acl(&bytes[offset..], false).map_err(|_| NativeError::Other)?;
    Ok(false)
}

/// Compares only copied bounded owner/user SIDs; neither principal leaves memory.
fn owner_is_user(token: &OwnedHandle) -> Result<bool, NativeError> {
    let buffer = TokenBuffer::read(token, TokenOwner)?;
    let owner = buffer.sid(buffer.header::<TOKEN_OWNER>()?.Owner)?;
    let user = token_user_sid(token)?;
    Ok(owner.bytes() == user.bytes())
}

/// Emits separate API-query, validated-null and private owner-equality observations.
fn token_fields(subject: &str, token: &OwnedHandle) -> Vec<String> {
    let buffer = TokenBuffer::read(token, TokenDefaultDacl);
    let dacl = buffer.as_ref().ok().map(default_dacl);
    let owner = owner_is_user(token);
    [
        ("default-dacl-query-ok", buffer.is_ok()),
        (
            "default-dacl-valid",
            dacl.as_ref().is_some_and(|result| result.is_ok()),
        ),
        (
            "default-dacl-null",
            dacl.as_ref()
                .is_some_and(|result| result.as_ref().is_ok_and(|value| *value)),
        ),
        ("owner-query-ok", owner.is_ok()),
        (
            "owner-equals-user",
            owner.as_ref().is_ok_and(|value| *value),
        ),
    ]
    .iter()
    .map(|(key, value)| format!("{subject}-{key}={value}"))
    .collect()
}

/// Refuses generic/unsupported ACEs instead of guessing undocumented kernel object mappings.
fn ordinary_descriptor(descriptor: &Descriptor, generic_free: bool) -> Result<(), NativeError> {
    // SAFETY: descriptor already validated the complete relative header and every allocation offset.
    let header = unsafe {
        descriptor
            .storage
            .as_ptr()
            .cast::<windows::Win32::Security::SECURITY_DESCRIPTOR_RELATIVE>()
            .read()
    };
    if header.Dacl == 0 {
        return Ok(());
    }
    // SAFETY: retained owned initialized bytes; validation bounds the complete ordinary ACE/SID table.
    let bytes = unsafe {
        std::slice::from_raw_parts(descriptor.storage.as_ptr().cast::<u8>(), descriptor.length)
    };
    object_acl::validate_acl(&bytes[header.Dacl as usize..], generic_free)
        .map_err(|_| NativeError::Other)
}

/// Runs DACL-only checks on fixed masks; unavailable is distinct from access denied.
fn access_fields(
    fields: &mut Vec<String>,
    object: &str,
    descriptor: Option<&Descriptor>,
    source: &OwnedHandle,
    derived: &OwnedHandle,
    actual: Option<&OwnedHandle>,
) {
    let is_token = object == "token";
    let mapping = if is_token {
        // Documented SDK token generic rights; tokens have no SYNCHRONIZE right.
        GENERIC_MAPPING {
            GenericRead: TOKEN_READ.0,
            GenericWrite: TOKEN_WRITE.0,
            GenericExecute: TOKEN_EXECUTE.0,
            GenericAll: TOKEN_ALL_ACCESS.0,
        }
    } else {
        // Every desired/ACE mask is proved generic-free below. This valid structure
        // is unused for translation; it is NOT a claimed process/thread kernel mapping.
        GENERIC_MAPPING::default()
    };
    let query = match object {
        "process" => PROCESS_QUERY_LIMITED_INFORMATION.0,
        "thread" => THREAD_QUERY_LIMITED_INFORMATION.0,
        _ => TOKEN_QUERY.0,
    };
    let synchronize = if object == "process" {
        PROCESS_SYNCHRONIZE.0
    } else {
        THREAD_SYNCHRONIZE.0
    };
    let all = match object {
        "process" => PROCESS_ALL_ACCESS.0,
        "thread" => THREAD_ALL_ACCESS.0,
        _ => TOKEN_ALL_ACCESS.0,
    };
    // ALL_ACCESS is an observation only; denial/reserved rights do not identify a loader cause.
    for (subject, token) in [
        ("source", Some(source)),
        ("derived", Some(derived)),
        ("actual", actual),
    ] {
        for (tag, desired) in [
            ("read-control", READ_CONTROL_MASK),
            ("query", query),
            ("synchronize", synchronize),
            ("all", all),
        ] {
            if is_token && tag == "synchronize" {
                continue;
            }
            let result = descriptor.zip(token).map(|(descriptor, token)| {
                ordinary_descriptor(descriptor, !is_token)?;
                if desired & 0xf000_0000 != 0 {
                    return Err(NativeError::Other);
                }
                dacl_access(descriptor, token, desired, &mapping)
            });
            fields.push(format!(
                "{subject}-{object}-{tag}-query-ok={}",
                result.as_ref().is_some_and(|result| result.is_ok())
            ));
            fields.push(format!(
                "{subject}-{object}-{tag}-allowed={}",
                result
                    .as_ref()
                    .is_some_and(|result| result.as_ref().is_ok_and(|value| *value))
            ));
        }
    }
}

/// Observes only this owned, already-proved suspended child; never borrows/looks up other PIDs.
pub(super) fn observe(
    source: &OwnedHandle,
    derived: &OwnedHandle,
    child: &OwnedChild,
    fixture: &Fixture,
) {
    let mut fields = token_fields("source", source);
    fields.extend(token_fields("derived", derived));
    let process = descriptor(child.process.0).ok();
    let thread = descriptor(child.thread.0).ok();
    let mut handle = HANDLE::default();
    // SAFETY: exact retained owned child process; separate observer opening changes no proof handle.
    let opening = unsafe {
        OpenProcessToken(
            child.process.0,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_READ_CONTROL,
            &mut handle,
        )
    };
    let token = opening.ok().map(|()| OwnedHandle(handle));
    let token_descriptor = token.as_ref().and_then(|token| descriptor(token.0).ok());
    fields.push(format!("child-token-open-query-ok={}", token.is_some()));
    for (object, observed) in [
        ("process", process.as_ref()),
        ("thread", thread.as_ref()),
        ("token", token_descriptor.as_ref()),
    ] {
        fields.push(format!(
            "child-{object}-descriptor-query-ok={}",
            observed.is_some()
        ));
        access_fields(
            &mut fields,
            object,
            observed,
            source,
            derived,
            token.as_ref(),
        );
    }
    effective_context::observe(source, derived, token.as_ref(), child, fixture);
    // Local query handle drops independently; original image/token proof and child lifecycle stay unchanged.
    println!("openrdx-token-object-context {}", fields.join(" "));
}

/// Nullable/default-DACL metadata never dereferences outside the bounded token response.
#[test]
fn default_dacl_bounds_fail_closed() {
    let mut buffer = TokenBuffer {
        storage: vec![0_usize; 4],
        length: size_of::<usize>() * 4,
    };
    assert!(default_dacl(&buffer) == Ok(true));
    let start = buffer.storage.as_ptr() as usize;
    let offset = size_of::<TOKEN_DEFAULT_DACL>();
    // SAFETY: synthetic aligned header points to an eight-byte empty ACL within owned storage.
    unsafe {
        buffer.storage.as_mut_ptr().write(start + offset);
        let bytes =
            std::slice::from_raw_parts_mut(buffer.storage.as_mut_ptr().cast::<u8>(), buffer.length);
        bytes[offset..offset + 8].copy_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    }
    assert!(default_dacl(&buffer) == Ok(false));
    // SAFETY: deliberately misaligned synthetic address is rejected before dereference.
    unsafe { buffer.storage.as_mut_ptr().write(start + offset + 1) };
    assert!(default_dacl(&buffer).is_err());
    // SAFETY: initialized aligned synthetic header; address is deliberately outside owned storage.
    unsafe { buffer.storage.as_mut_ptr().write(1) };
    assert!(default_dacl(&buffer).is_err());
    buffer.length = 0;
    assert!(default_dacl(&buffer).is_err());
}
