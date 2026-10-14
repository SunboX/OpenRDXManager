// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test-only factory lineage: DACL writes can reach a fresh restricted token, never a source handle.
use super::process_dacl_control::process_descriptor::{Components, ObjectRole};
use super::process_dacl_control::{PrivateDescriptor, source_default_dacl};
use super::*;
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, SetKernelObjectSecurity, TOKEN_READ_CONTROL, TOKEN_WRITE_DAC,
};

/// Read-only source observer is captured before opening any derivation handle with WRITE_DAC.
pub(super) struct SourceGuard {
    observer: OwnedHandle,
    statistics: token_statistics::Statistics,
    pub(super) snapshot: SourceSnapshot,
    descriptor: Components,
    default_dacl: Option<Vec<u8>>,
    pub(super) console: OwnedSid,
    pub(super) session: u32,
    pub(super) user: OwnedSid,
}
impl SourceGuard {
    /// Pins source properties/default DACL/object descriptor before granting new handle rights.
    pub(super) fn capture() -> Result<Self, NativeError> {
        let mut raw = HANDLE::default();
        // SAFETY: borrowed current process; owned read-only observer, no source setter exists.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_READ_CONTROL,
                &mut raw,
            )
        }
        .map_err(map_native_error)?;
        let observer = OwnedHandle(raw);
        let statistics = token_statistics::Statistics::read(&observer);
        let snapshot = SourceSnapshot::read(&observer)?;
        let descriptor = PrivateDescriptor::read(observer.0)?.components;
        let default_dacl = source_default_dacl(&observer)?;
        // SAFETY: read-only console identity; no session/UAC/account change.
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err(NativeError::AccessDenied);
        }
        let console = console_sid(session)?;
        if snapshot.user != console.bytes()
            || snapshot.session != session
            || snapshot.elevation == 0
            || snapshot.integrity != 0x3000
            || snapshot.token_type != 1
        {
            return Err(NativeError::AccessDenied);
        }
        let user = token_user_sid(&observer)?;
        Ok(Self {
            observer,
            statistics,
            snapshot,
            descriptor,
            default_dacl,
            console,
            session,
            user,
        })
    }

    /// Retains pre-WRITE_DAC identity and queries the same held source only; metadata is observational.
    pub(super) fn statistics(
        &self,
    ) -> (token_statistics::Statistics, token_statistics::Statistics) {
        (
            self.statistics,
            token_statistics::Statistics::read(&self.observer),
        )
    }

    /// Compares every source property and canonical object/default ACL without pointer-bearing headers.
    pub(super) fn observations(&self) -> Result<[bool; 3], NativeError> {
        let snapshot = SourceSnapshot::read(&self.observer)?;
        let descriptor = PrivateDescriptor::read(self.observer.0)?.components;
        let default = source_default_dacl(&self.observer)?;
        Ok([
            snapshot == self.snapshot,
            default == self.default_dacl,
            descriptor == self.descriptor,
        ])
    }

    /// Rejects any source mismatch or unavailable read rather than continuing another launch.
    pub(super) fn unchanged(&self) -> Result<(), NativeError> {
        if self.observations()?.into_iter().all(|value| value) {
            Ok(())
        } else {
            Err(NativeError::AccessDenied)
        }
    }

    /// Opens rights required only for a fresh derived object; granting rights is not a source mutation.
    fn derivation_handle(&self, row: Row) -> Result<OwnedHandle, NativeError> {
        let unchanged = self.unchanged();
        facts(
            row.name(),
            "derive",
            &[("source-observer-unchanged", unchanged.is_ok())],
        );
        unchanged?;
        let mut raw = HANDLE::default();
        // CreateRestrictedToken returns exactly the source handle's granted access rights.
        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
        // SAFETY: current-process source only; no adjustment call ever receives this handle.
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY
                    | TOKEN_DUPLICATE
                    | TOKEN_ASSIGN_PRIMARY
                    | TOKEN_ADJUST_DEFAULT
                    | TOKEN_READ_CONTROL
                    | TOKEN_WRITE_DAC,
                &mut raw,
            )
        }
        .map_err(map_native_error);
        // Own a successful SDK handle before any diagnostic write can panic.
        let source = opened.as_ref().ok().map(|_| OwnedHandle(raw));
        facts(
            row.name(),
            "derive",
            &[("source-rights-open", opened.is_ok())],
        );
        opened?;
        let source = source.ok_or(NativeError::Other)?;
        let exact = SourceSnapshot::read(&source)? == self.snapshot
            && PrivateDescriptor::read(source.0)?.components == self.descriptor
            && source_default_dacl(&source)? == self.default_dacl;
        facts(row.name(), "derive", &[("source-handle-exact", exact)]);
        if !exact {
            return Err(NativeError::AccessDenied);
        }
        self.unchanged()?;
        Ok(source)
    }
}

/// No raw constructor, From, Deref or source adoption; only the private restricted-token factory constructs it.
pub(super) struct FreshDerivedToken {
    handle: OwnedHandle,
    statistics: token_statistics::Statistics,
    snapshot: SourceSnapshot,
    descriptor: Components,
    default_dacl: Option<Vec<u8>>,
    adjusted: bool,
}
impl FreshDerivedToken {
    /// Owns one new CRT token and performs only the already-approved fresh-token medium reduction.
    pub(super) fn create(source: &SourceGuard, row: Row) -> Result<Self, NativeError> {
        let parent = source.derivation_handle(row)?;
        let mut raw = HANDLE::default();
        // SAFETY: fixed source lineage/approved flags, no caller tables or SANDBOX_INERT.
        let created = unsafe {
            CreateRestrictedToken(
                parent.0,
                LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
                None,
                None,
                None,
                &mut raw,
            )
        }
        .map_err(map_native_error);
        // Factory lineage and ownership are established immediately after API success.
        let handle = created.as_ref().ok().map(|_| OwnedHandle(raw));
        facts(
            row.name(),
            "derive",
            &[("restricted-created", created.is_ok())],
        );
        created?;
        let handle = handle.ok_or(NativeError::Other)?;
        let medium = set_medium(&handle);
        facts(row.name(), "derive", &[("medium-set", medium.is_ok())]);
        medium?;
        let statistics = token_statistics::Statistics::read(&handle);
        let snapshot = SourceSnapshot::read(&handle)?;
        let (denied, no_admins) = administrative_groups(&handle)?;
        let reduced = eligible(
            &snapshot,
            &source.snapshot,
            &source.console,
            source.session,
            denied,
            no_admins,
        )? && snapshot.privileges.len() < source.snapshot.privileges.len();
        facts(row.name(), "derive", &[("reduced-proved", reduced)]);
        if !reduced {
            return Err(NativeError::AccessDenied);
        }
        let descriptor = PrivateDescriptor::read(handle.0)?.components;
        let default_dacl = source_default_dacl(&handle)?;
        source.unchanged()?;
        Ok(Self {
            handle,
            statistics,
            snapshot,
            descriptor,
            default_dacl,
            adjusted: false,
        })
    }

    /// Captures fresh-current metadata separately from factory metadata; no raw token handle is adopted.
    pub(super) fn statistics(
        &self,
    ) -> (token_statistics::Statistics, token_statistics::Statistics) {
        (
            self.statistics,
            token_statistics::Statistics::read(&self.handle),
        )
    }

    /// Borrows query/launch ownership only; no mutable/raw-adoption interface is provided.
    pub(super) fn launch_token(&self) -> &OwnedHandle {
        &self.handle
    }

    /// Adds exactly one concrete token-object user ACE; never writes source/default DACL/owner/LABEL.
    pub(super) fn add_object_user_allow(
        &mut self,
        source: &SourceGuard,
    ) -> Result<(), NativeError> {
        if self.adjusted || self.snapshot.user != source.user.bytes() {
            return Err(NativeError::AccessDenied);
        }
        self.unchanged(false, source)?;
        let expected = self
            .descriptor
            .with_user_allow(source.user.bytes(), ObjectRole::Token)
            .map_err(|_| NativeError::Other)?;
        let owned =
            PrivateDescriptor::from_bytes(&expected.bytes().map_err(|_| NativeError::Other)?)?;
        // TOKEN object security is documented Get/SetKernelObjectSecurity, not TokenDefaultDacl.
        // https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
        // SAFETY: factory-exclusive fresh object, explicitly granted WRITE_DAC, aligned live validated SD.
        unsafe {
            SetKernelObjectSecurity(self.handle.0, DACL_SECURITY_INFORMATION, owned.pointer())
        }
        .map_err(map_native_error)?;
        self.adjusted = true;
        // Caller emits the complete private readback booleans before enforcing exact preservation.
        Ok(())
    }

    /// Emits only private equality results; original reductions and all non-DACL components stay exact.
    pub(super) fn preservation(
        &self,
        token_control: bool,
        source: &SourceGuard,
    ) -> Result<[bool; 7], NativeError> {
        let observed = PrivateDescriptor::read(self.handle.0)?.components;
        let expected = if token_control {
            self.descriptor
                .with_user_allow(source.user.bytes(), ObjectRole::Token)
                .map_err(|_| NativeError::Other)?
        } else {
            self.descriptor.clone()
        };
        let kept = observed.preservation(&self.descriptor);
        Ok([
            kept[0],
            kept[1],
            kept[2],
            kept[3],
            observed == expected,
            SourceSnapshot::read(&self.handle)? == self.snapshot,
            source_default_dacl(&self.handle)? == self.default_dacl,
        ])
    }

    /// Requires exact DACL intervention, source preservation and every original reduction.
    pub(super) fn unchanged(
        &self,
        token_control: bool,
        source: &SourceGuard,
    ) -> Result<(), NativeError> {
        if !self
            .preservation(token_control, source)?
            .into_iter()
            .all(|value| value)
        {
            return Err(NativeError::AccessDenied);
        }
        source.unchanged()
    }
}
