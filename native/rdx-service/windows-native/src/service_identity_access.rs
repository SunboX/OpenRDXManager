// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private role-specific metadata grants for mutually verified desktop/service peers.

#[cfg(test)]
mod manager_tests;
mod policy;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

use crate::NativeError;
use policy::Descriptor;

/// Sole installed Manager image path; never selected by environment, IPC or FFI arguments.
pub(crate) const MANAGER_IMAGE: &str = r"C:\Program Files\OpenRDXManager\OpenRDXManager.exe";

/// Opaque SID derived solely by the fixed native service-account lookup.
struct FixedServiceSid([u8; 32]);

/// Bounds a successful lookup's capacity value separately from validated actual SID length.
fn fixed_service_lookup_capacity_valid(reported: u32, allocated: usize) -> bool {
    (32..=68).contains(&allocated) && (32..=allocated).contains(&(reported as usize))
}

/// Requires the fixed kernel image path and matching current/pinned file identities.
pub(crate) fn manager_identity_matches(
    path: &[u16],
    current: [u32; 3],
    kernel: [u32; 3],
    expected: [u32; 3],
    pinned: bool,
) -> bool {
    // This fixed path is ASCII. Accept only ordinal ASCII case changes in its
    // normal Win32 form, never aliases, dot segments, alternate roots or NULs.
    path.len() == MANAGER_IMAGE.len()
        && path
            .iter()
            .zip(MANAGER_IMAGE.bytes())
            .all(|(actual, expected)| {
                *actual <= 0x7f && (*actual as u8).eq_ignore_ascii_case(&expected)
            })
        && pinned
        && current == expected
        && kernel == expected
}

/// Serializes idempotent current-Manager process grants; never touches its primary token.
/// This orders our workers; external WRITE_DAC holders are outside the mutex's scope.
fn grant_manager_query_access(
    objects: &impl CurrentObjects,
    sid: &FixedServiceSid,
) -> Result<(), NativeError> {
    static MUTATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serialization = MUTATION.lock().map_err(|_| NativeError::AccessDenied)?;
    let before = objects.read(Object::Process)?;
    let expected = before.with_manager_query_access(sid)?;
    if expected != before {
        objects.set_dacl(Object::Process, &expected)?;
    }
    // Even a reconnect with no mutation must retain exact current evidence.
    if objects.read(Object::Process)? != expected {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

/// Closed current-object roles; neither callers nor IPC can choose a PID, SID or mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Object {
    Process,
    PrimaryToken,
}

impl Object {
    /// Returns only the concrete query right used by the existing client identity checks.
    const fn query_mask(self) -> u32 {
        match self {
            Self::Process => 0x1000,
            Self::PrimaryToken => 0x8,
        }
    }
}

/// Private native boundary; each implementation retains handles to its own objects only.
trait CurrentObjects {
    /// Copies bounded owner/group/control/DACL/mandatory-label evidence.
    fn read(&self, object: Object) -> Result<Descriptor, NativeError>;
    /// Changes only the selected current object's DACL; all failures are fatal to startup.
    fn set_dacl(&self, object: Object, descriptor: &Descriptor) -> Result<(), NativeError>;
}

/// Preflights both objects and requires exact readback before returning startup authority.
fn grant_query_access(objects: &impl CurrentObjects) -> Result<(), NativeError> {
    let process = objects
        .read(Object::Process)?
        .with_query_access(Object::Process)?;
    let token = objects
        .read(Object::PrimaryToken)?
        .with_query_access(Object::PrimaryToken)?;
    for (object, expected) in [(Object::Process, process), (Object::PrimaryToken, token)] {
        objects.set_dacl(object, &expected)?;
        if objects.read(object)? != expected {
            return Err(NativeError::AccessDenied);
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) use windows::manager::prepare_current_manager_identity_queries;
#[cfg(windows)]
pub(super) use windows::prepare_current_service_identity_queries;
