// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only test diagnostics: DACL access is not effective MIC or loader proof.
//! Access-allowed fields cover object-specific masks only, excluding standard
//! security-mutation rights; they do not assert full desktop/window-station access.
use super::*;
use std::ffi::c_void;
use windows::Win32::Security::{
    AccessCheck, DuplicateTokenEx, GENERIC_MAPPING, IsValidSecurityDescriptor, IsWellKnownSid,
    PRIVILEGE_SET, PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_RELATIVE, SecurityImpersonation,
    TokenImpersonation, WinBatchSid, WinInteractiveSid, WinServiceSid,
};
use windows::Win32::System::Threading::GetCurrentThreadId;

/// SDK WinUser.h object-specific WINSTA_ALL_ACCESS; generic-all also includes standard rights.
/// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinUser.h
const STATION_ALL: u32 = 0x037f;
/// All documented desktop-specific rights, excluding unrelated security mutation requests.
const DESKTOP_SPECIFIC: u32 = 0x01ff;
/// SDK STANDARD_RIGHTS_REQUIRED used by interactive generic mappings.
const STANDARD_REQUIRED: u32 = 0x000f_0000;
/// READ_CONTROL reads owner/group/DACL without requesting SACL privilege.
const READ_CONTROL_MASK: u32 = 0x0002_0000;

#[link(name = "user32")]
unsafe extern "system" {
    /// Borrows the current station; it must never be closed by this diagnostic.
    fn GetProcessWindowStation() -> HANDLE;
    /// Borrows the current thread's desktop; it must never be closed here.
    fn GetThreadDesktop(thread: u32) -> HANDLE;
    /// Queries bounded object metadata without changing the object.
    fn GetUserObjectInformationW(
        object: HANDLE,
        index: i32,
        buffer: *mut c_void,
        bytes: u32,
        needed: *mut u32,
    ) -> i32;
    /// Opens only a fixed local station with read-only security-query access.
    fn OpenWindowStationW(name: PCWSTR, inherit: i32, access: u32) -> HANDLE;
    /// Closes only successfully opened owned station handles.
    fn CloseWindowStation(station: HANDLE) -> i32;
    /// Opens a fixed desktop in the current station, without changing station association.
    fn OpenDesktopW(name: PCWSTR, flags: u32, inherit: i32, access: u32) -> HANDLE;
    /// Closes only successfully opened owned desktop handles.
    fn CloseDesktop(desktop: HANDLE) -> i32;
    /// Reads owner/group/DACL only into bounded caller-owned descriptor storage.
    fn GetUserObjectSecurity(
        object: HANDLE,
        information: *const u32,
        buffer: *mut c_void,
        bytes: u32,
        needed: *mut u32,
    ) -> i32;
}

/// Owns only an explicitly opened station, separately from borrowed current handles.
struct Station(HANDLE);
impl Drop for Station {
    /// Uses the station-specific close API on this owned opening only.
    fn drop(&mut self) {
        unsafe { CloseWindowStation(self.0) };
    }
}
/// Owns only an explicitly opened desktop, separately from borrowed thread handles.
struct Desktop(HANDLE);
impl Drop for Desktop {
    /// Uses the desktop-specific close API on this owned opening only.
    fn drop(&mut self) {
        unsafe { CloseDesktop(self.0) };
    }
}

/// Internally compares one bounded object name; no name is returned or printed.
fn object_is(object: HANDLE, expected: &str) -> Result<bool, NativeError> {
    if object.is_invalid() {
        return Err(NativeError::Other);
    }
    let mut needed = 0;
    // SAFETY: borrowed valid object, sizing query has no writable payload.
    unsafe { GetUserObjectInformationW(object, 2, std::ptr::null_mut(), 0, &mut needed) };
    if !(2..=1024).contains(&needed) || needed % 2 != 0 {
        return Err(NativeError::Other);
    }
    let mut name = vec![0_u16; needed as usize / 2];
    let capacity = needed;
    // SAFETY: bounded writable UTF-16 storage; output length is rechecked.
    if unsafe {
        GetUserObjectInformationW(object, 2, name.as_mut_ptr().cast(), capacity, &mut needed)
    } == 0
        || needed > capacity
        || needed < 2
        || needed % 2 != 0
    {
        return Err(NativeError::Other);
    }
    let units = &name[..needed as usize / 2];
    let end = units
        .iter()
        .position(|value| *value == 0)
        .ok_or(NativeError::Other)?;
    Ok(String::from_utf16(&units[..end])
        .map_err(|_| NativeError::Other)?
        .eq_ignore_ascii_case(expected))
}

/// Private token groups: identities remain owned in memory without Debug/output.
struct Groups {
    logon: Option<Vec<u8>>,
    interactive: bool,
    batch: bool,
    service: bool,
}
/// Reads bounded groups and exactly one logon SID, reporting only booleans later.
fn groups(token: &OwnedHandle) -> Result<Groups, NativeError> {
    let buffer = TokenBuffer::read(token, TokenGroups)?;
    let entries = buffer
        .entries::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), buffer.header::<u32>()?)?;
    let mut observed = Groups {
        logon: None,
        interactive: false,
        batch: false,
        service: false,
    };
    let mut logons = 0;
    for entry in entries {
        let sid = buffer.sid(entry.Sid)?;
        if entry.Attributes & 0xc000_0000 == 0xc000_0000 {
            logons += 1;
            observed.logon = Some(sid.bytes().to_vec());
        }
        if entry.Attributes & GROUP_ENABLED != 0 && entry.Attributes & GROUP_DENY_ONLY == 0 {
            // SAFETY: internally copied validated SID; fixed well-known classifications only.
            observed.interactive |=
                unsafe { IsWellKnownSid(sid.pointer(), WinInteractiveSid).as_bool() };
            observed.batch |= unsafe { IsWellKnownSid(sid.pointer(), WinBatchSid).as_bool() };
            observed.service |= unsafe { IsWellKnownSid(sid.pointer(), WinServiceSid).as_bool() };
        }
    }
    if logons != 1 {
        observed.logon = None;
    }
    Ok(observed)
}

/// Aligned, bounded self-relative security descriptor with private principals.
struct Descriptor {
    storage: Vec<usize>,
    length: usize,
}
impl Descriptor {
    /// Reads owner/group/DACL only; no SACL, security privilege or mutation request.
    fn read(object: HANDLE) -> Result<Self, NativeError> {
        let information = 1 | 2 | 4;
        let mut needed = 0;
        // SAFETY: live user-object handle; sizing output only.
        unsafe {
            GetUserObjectSecurity(object, &information, std::ptr::null_mut(), 0, &mut needed)
        };
        if !(size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=MAX_PROBE_BYTES)
            .contains(&(needed as usize))
        {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = storage.len() * size_of::<usize>();
        // SAFETY: initialized aligned storage is writable for its declared bounded capacity.
        if unsafe {
            GetUserObjectSecurity(
                object,
                &information,
                storage.as_mut_ptr().cast(),
                capacity as u32,
                &mut needed,
            )
        } == 0
            || needed as usize > capacity
            || (needed as usize) < size_of::<SECURITY_DESCRIPTOR_RELATIVE>()
        {
            return Err(NativeError::Other);
        }
        let descriptor = Self {
            storage,
            length: needed as usize,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
    /// Returns only a pointer inside this owned live allocation.
    fn pointer(&self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR(self.storage.as_ptr().cast_mut().cast())
    }
    /// Rejects incomplete/absolute descriptors before passing them to access-check APIs.
    fn validate(&self) -> Result<(), NativeError> {
        // SAFETY: complete aligned fixed header fits inside actual initialized response.
        let header = unsafe {
            self.storage
                .as_ptr()
                .cast::<SECURITY_DESCRIPTOR_RELATIVE>()
                .read()
        };
        if header.Control.0 & 0x8000 == 0
            || header.Owner == 0
            || header.Group == 0
            || header.Sacl != 0
        {
            return Err(NativeError::Other);
        }
        let start = self.storage.as_ptr() as usize;
        for offset in [header.Owner, header.Group] {
            if offset % 4 != 0
                || (offset as usize) < size_of::<SECURITY_DESCRIPTOR_RELATIVE>()
                || (offset as usize) >= self.length
            {
                return Err(NativeError::Other);
            }
            copy_bounded_sid(
                PSID((start + offset as usize) as *mut c_void),
                start,
                self.length,
            )?;
        }
        if header.Dacl != 0 {
            let offset = header.Dacl as usize;
            if offset % 4 != 0
                || offset < size_of::<SECURITY_DESCRIPTOR_RELATIVE>()
                || offset.checked_add(8).is_none_or(|end| end > self.length)
            {
                return Err(NativeError::Other);
            }
            // SAFETY: descriptor response contains the bounded initialized bytes being inspected.
            let bytes = unsafe {
                std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.length)
            };
            let size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            let count = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]);
            let end = offset
                .checked_add(size)
                .filter(|end| size >= 8 && *end <= self.length)
                .ok_or(NativeError::Other)?;
            let mut cursor = offset + 8;
            for _ in 0..count {
                if cursor.checked_add(4).is_none_or(|limit| limit > end) {
                    return Err(NativeError::Other);
                }
                let size = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
                cursor = cursor
                    .checked_add(size)
                    .filter(|limit| size >= 4 && *limit <= end)
                    .ok_or(NativeError::Other)?;
            }
        }
        // SAFETY: all descriptor offsets/table extents are bounded above within live storage.
        if !unsafe { IsValidSecurityDescriptor(self.pointer()).as_bool() } {
            return Err(NativeError::Other);
        }
        Ok(())
    }
}

/// Creates an owned impersonation-TYPE query copy only; never impersonates a thread.
fn query_copy(token: &OwnedHandle) -> Result<OwnedHandle, NativeError> {
    let mut handle = HANDLE::default();
    // SAFETY: borrowed source/derived token, query-only owned duplicate output.
    unsafe {
        DuplicateTokenEx(
            token.0,
            TOKEN_QUERY,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut handle,
        )
    }
    .map_err(map_native_error)?;
    Ok(OwnedHandle(handle))
}

/// Checks object-specific DACL rights only, excluding standard rights, MIC and loader readiness.
fn dacl_allowed(
    descriptor: &Descriptor,
    token: &OwnedHandle,
    station: bool,
) -> Result<bool, NativeError> {
    let token = query_copy(token)?;
    // Interactive object generic mappings from the documented SDK access-right tables.
    let mapping = if station {
        GENERIC_MAPPING {
            GenericRead: READ_CONTROL_MASK | 0x0303,
            GenericWrite: READ_CONTROL_MASK | 0x001c,
            GenericExecute: READ_CONTROL_MASK | 0x0060,
            GenericAll: STANDARD_REQUIRED | STATION_ALL,
        }
    } else {
        GENERIC_MAPPING {
            GenericRead: READ_CONTROL_MASK | 0x0041,
            GenericWrite: READ_CONTROL_MASK | 0x00be,
            GenericExecute: READ_CONTROL_MASK | 0x0100,
            GenericAll: STANDARD_REQUIRED | DESKTOP_SPECIFIC,
        }
    };
    let desired = if station {
        STATION_ALL
    } else {
        DESKTOP_SPECIFIC
    };
    let mut privileges = vec![0_usize; MAX_PROBE_BYTES / size_of::<usize>()];
    let mut bytes = MAX_PROBE_BYTES as u32;
    let mut granted = 0;
    let mut allowed = windows::core::BOOL::default();
    // SAFETY: bounded descriptor, owned query copy, fixed mapped mask, initialized outputs.
    unsafe {
        AccessCheck(
            descriptor.pointer(),
            token.0,
            desired,
            &mapping,
            Some(privileges.as_mut_ptr().cast::<PRIVILEGE_SET>()),
            &mut bytes,
            &mut granted,
            &mut allowed,
        )
    }
    .map_err(map_native_error)?;
    if bytes as usize > MAX_PROBE_BYTES {
        return Err(NativeError::Other);
    }
    Ok(allowed.as_bool() && granted & desired == desired)
}

/// Emits independently queryable fixed facts without changing the existing child attempt/result.
pub(super) fn observe(source: &OwnedHandle, derived: &OwnedHandle) {
    let source_groups = groups(source).ok();
    let derived_groups = groups(derived).ok();
    // SAFETY: these APIs return borrowed handles, never wrapped in owned close guards.
    let current_station = object_is(unsafe { GetProcessWindowStation() }, "WinSta0");
    let current_desktop = object_is(unsafe { GetThreadDesktop(GetCurrentThreadId()) }, "Default");
    let current_station_is_fixed = current_station.as_ref().is_ok_and(|value| *value);
    let name = wide_null(OsStr::new("WinSta0"));
    // SAFETY: fixed local station name, no inheritance, read-only owner/group/DACL query.
    let station_handle = unsafe { OpenWindowStationW(PCWSTR(name.as_ptr()), 0, READ_CONTROL_MASK) };
    let station = if station_handle.is_invalid() {
        None
    } else {
        Some(Station(station_handle))
    };
    let station_descriptor = station
        .as_ref()
        .and_then(|owned| Descriptor::read(owned.0).ok());
    // OpenDesktop addresses only the current station: never query an unrelated Default.
    let desktop = if current_station_is_fixed {
        let name = wide_null(OsStr::new("Default"));
        // READ_CONTROL requires READOBJECTS|WRITEOBJECTS; no object-writing API is called.
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-opendesktopw
        // SAFETY: verified current station, fixed name, no hooks/inheritance or station switch.
        let handle = unsafe { OpenDesktopW(PCWSTR(name.as_ptr()), 0, 0, READ_CONTROL_MASK | 0x81) };
        if handle.is_invalid() {
            None
        } else {
            Some(Desktop(handle))
        }
    } else {
        None
    };
    let desktop_descriptor = desktop
        .as_ref()
        .and_then(|owned| Descriptor::read(owned.0).ok());
    let source_station = station_descriptor
        .as_ref()
        .map(|sd| dacl_allowed(sd, source, true));
    let derived_station = station_descriptor
        .as_ref()
        .map(|sd| dacl_allowed(sd, derived, true));
    let source_desktop = desktop_descriptor
        .as_ref()
        .map(|sd| dacl_allowed(sd, source, false));
    let derived_desktop = desktop_descriptor
        .as_ref()
        .map(|sd| dacl_allowed(sd, derived, false));
    let same_logon = source_groups
        .as_ref()
        .zip(derived_groups.as_ref())
        .is_some_and(|(a, b)| {
            a.logon
                .as_ref()
                .zip(b.logon.as_ref())
                .is_some_and(|(a, b)| a == b)
        });
    let facts = [
        ("source-groups-query-ok", source_groups.is_some()),
        (
            "source-logon-single",
            source_groups.as_ref().is_some_and(|g| g.logon.is_some()),
        ),
        ("derived-groups-query-ok", derived_groups.is_some()),
        (
            "derived-logon-single",
            derived_groups.as_ref().is_some_and(|g| g.logon.is_some()),
        ),
        ("logon-same", same_logon),
        (
            "source-interactive-enabled",
            source_groups.as_ref().is_some_and(|g| g.interactive),
        ),
        (
            "source-batch-enabled",
            source_groups.as_ref().is_some_and(|g| g.batch),
        ),
        (
            "source-service-enabled",
            source_groups.as_ref().is_some_and(|g| g.service),
        ),
        (
            "derived-interactive-enabled",
            derived_groups.as_ref().is_some_and(|g| g.interactive),
        ),
        (
            "derived-batch-enabled",
            derived_groups.as_ref().is_some_and(|g| g.batch),
        ),
        (
            "derived-service-enabled",
            derived_groups.as_ref().is_some_and(|g| g.service),
        ),
        ("current-station-query-ok", current_station.is_ok()),
        ("current-station-winsta-zero", current_station_is_fixed),
        ("current-desktop-query-ok", current_desktop.is_ok()),
        (
            "current-desktop-default",
            current_desktop.as_ref().is_ok_and(|v| *v),
        ),
        ("station-descriptor-query-ok", station_descriptor.is_some()),
        ("desktop-descriptor-query-ok", desktop_descriptor.is_some()),
        (
            "source-station-access-query-ok",
            source_station.as_ref().is_some_and(|r| r.is_ok()),
        ),
        (
            "source-station-access-allowed",
            source_station
                .as_ref()
                .is_some_and(|r| r.as_ref().is_ok_and(|v| *v)),
        ),
        (
            "derived-station-access-query-ok",
            derived_station.as_ref().is_some_and(|r| r.is_ok()),
        ),
        (
            "derived-station-access-allowed",
            derived_station
                .as_ref()
                .is_some_and(|r| r.as_ref().is_ok_and(|v| *v)),
        ),
        (
            "source-desktop-access-query-ok",
            source_desktop.as_ref().is_some_and(|r| r.is_ok()),
        ),
        (
            "source-desktop-access-allowed",
            source_desktop
                .as_ref()
                .is_some_and(|r| r.as_ref().is_ok_and(|v| *v)),
        ),
        (
            "derived-desktop-access-query-ok",
            derived_desktop.as_ref().is_some_and(|r| r.is_ok()),
        ),
        (
            "derived-desktop-access-allowed",
            derived_desktop
                .as_ref()
                .is_some_and(|r| r.as_ref().is_ok_and(|v| *v)),
        ),
    ];
    let closed = facts
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!("openrdx-token-desktop-context {closed}");
}

/// Malformed descriptor headers fail before any native validator follows embedded pointers.
#[test]
fn descriptor_unusable_headers_are_unavailable() {
    use windows::Win32::Security::SECURITY_DESCRIPTOR_CONTROL;
    for (control, owner, group, sacl) in [
        (0, 24, 32, 0),
        (0x8000, 0, 32, 0),
        (0x8000, 24, 0, 0),
        (0x8000, 24, 32, 1),
        (0x8000, 23, 32, 0),
        (0x8000, u32::MAX, 32, 0),
    ] {
        let mut storage = vec![0_usize; 64 / size_of::<usize>()];
        let header = SECURITY_DESCRIPTOR_RELATIVE {
            Control: SECURITY_DESCRIPTOR_CONTROL(control),
            Owner: owner,
            Group: group,
            Sacl: sacl,
            ..Default::default()
        };
        // SAFETY: allocated aligned storage fits the entire initialized fixed header.
        unsafe {
            storage
                .as_mut_ptr()
                .cast::<SECURITY_DESCRIPTOR_RELATIVE>()
                .write(header)
        };
        let descriptor = Descriptor {
            storage,
            length: 64,
        };
        assert!(descriptor.validate() == Err(NativeError::Other));
    }
}

/// Invalid borrowed objects are unavailable and never reach an owned close guard.
#[test]
fn missing_borrowed_object_is_unavailable() {
    assert!(object_is(HANDLE::default(), "WinSta0") == Err(NativeError::Other));
}
