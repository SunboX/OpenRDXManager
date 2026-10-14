// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal test-only source rights; no source/derived DACL setter or raw adoption.
use super::super::token_statistics::Statistics;
use super::*;
use windows::Win32::Security::TOKEN_READ_CONTROL;

/// Private complete token state; metadata is compared only as known booleans.
pub(super) struct TokenState {
    pub(super) snapshot: SourceSnapshot,
    pub(super) descriptor: Components,
    pub(super) default: Option<Vec<u8>>,
    statistics: Statistics,
}
impl TokenState {
    /// All identity layouts must be exact before this intervention can be admitted.
    pub(super) fn read(handle: &OwnedHandle) -> Result<Self, NativeError> {
        let statistics = Statistics::read(handle);
        if !statistics.query_ok || !statistics.layout_valid {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(Self {
            snapshot: SourceSnapshot::read(handle)?,
            descriptor: PrivateDescriptor::read(handle.0)?.components,
            default: source_default_dacl(handle)?,
            statistics,
        })
    }
    /// Returns full properties/default ACL/object descriptor equality without private values.
    pub(super) fn preservation(&self, previous: &Self) -> [bool; 3] {
        [
            self.snapshot == previous.snapshot,
            self.default == previous.default,
            self.descriptor == previous.descriptor,
        ]
    }
    /// TokenId is object identity; logon/ModifiedId are observations, never object provenance.
    pub(super) fn identity(&self, other: &Self) -> [bool; 4] {
        self.statistics.compare(other.statistics)
    }
    /// Requires known stable object/logon and all original state; ModifiedId is observational only.
    pub(super) fn require_same(&self, previous: &Self) -> Result<(), NativeError> {
        let ids = self.identity(previous);
        if !(ids[0] && ids[1] && ids[2] && self.preservation(previous).iter().all(|v| *v)) {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }
}
/// Read-only source was captured before opening any derivation rights.
pub(super) struct SourceContext {
    observer: OwnedHandle,
    pub(super) state: TokenState,
    pub(super) user: OwnedSid,
    pub(super) console: OwnedSid,
    pub(super) session: u32,
}
impl SourceContext {
    /// Requires elevated high primary and exact current-console principal/session, without changes.
    pub(super) fn capture() -> Result<Self, NativeError> {
        let mut raw = HANDLE::default();
        // SAFETY: current-process borrowed handle; only owned query/read-control observer is opened.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_READ_CONTROL,
                &mut raw,
            )
        }
        .map_err(map_native_error)?;
        let observer = OwnedHandle(raw);
        let state = TokenState::read(&observer)?;
        // SAFETY: fixed read-only active-console query.
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err(NativeError::AccessDenied);
        }
        let console = console_sid(session)?;
        if state.snapshot.user != console.bytes()
            || state.snapshot.session != session
            || state.snapshot.elevation == 0
            || state.snapshot.integrity != 0x3000
            || state.snapshot.token_type != 1
        {
            return Err(NativeError::AccessDenied);
        }
        let user = token_user_sid(&observer)?;
        Ok(Self {
            observer,
            state,
            user,
            console,
            session,
        })
    }
    /// Reads the same held source, preserving all components and original complete properties.
    pub(super) fn observed(&self) -> Result<TokenState, NativeError> {
        TokenState::read(&self.observer)
    }
    /// Rejects unavailable/mismatched source; ModifiedId is not an immutability promise.
    pub(super) fn unchanged(&self) -> Result<(), NativeError> {
        self.observed()?.require_same(&self.state)
    }
    /// CRT inherits exactly these five rights; source WRITE_DAC is never requested.
    pub(super) fn derive_medium(&self) -> Result<MinimalDerivedToken, NativeError> {
        self.unchanged()?;
        let mut raw = HANDLE::default();
        // SAFETY: fixed minimal current-source handle. No source adjustment call receives it.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY
                    | TOKEN_DUPLICATE
                    | TOKEN_ASSIGN_PRIMARY
                    | TOKEN_ADJUST_DEFAULT
                    | TOKEN_READ_CONTROL,
                &mut raw,
            )
        }
        .map_err(map_native_error)?;
        let source = OwnedHandle(raw);
        TokenState::read(&source)?.require_same(&self.state)?;
        let mut raw = HANDLE::default();
        // SAFETY: same source, fixed approved flags and no arbitrary SID/privilege tables.
        unsafe {
            CreateRestrictedToken(
                source.0,
                LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
                None,
                None,
                None,
                &mut raw,
            )
        }
        .map_err(map_native_error)?;
        let handle = OwnedHandle(raw);
        set_medium(&handle)?;
        let state = TokenState::read(&handle)?;
        let (denied, no_admins) = administrative_groups(&handle)?;
        if !eligible(
            &state.snapshot,
            &self.state.snapshot,
            &self.console,
            self.session,
            denied,
            no_admins,
        )? || state.snapshot.privileges.len() >= self.state.snapshot.privileges.len()
        {
            return Err(NativeError::AccessDenied);
        }
        let identity = state.identity(&self.state);
        if !identity[0] || identity[1] {
            return Err(NativeError::AccessDenied);
        }
        self.unchanged()?;
        Ok(MinimalDerivedToken { handle, state })
    }
}
/// Only newly owned CRT token gets the existing medium setter; no object/default-DACL setter exists.
pub(super) struct MinimalDerivedToken {
    handle: OwnedHandle,
    pub(super) state: TokenState,
}
impl MinimalDerivedToken {
    /// Immutable borrow is used only by the fixed existing creation API.
    pub(super) fn launch_token(&self) -> &OwnedHandle {
        &self.handle
    }
    /// Strict preservation includes full properties, default ACL, object SD and known instance.
    pub(super) fn observed(&self) -> Result<TokenState, NativeError> {
        TokenState::read(&self.handle)
    }
    /// Source and derived state are both revalidated before another mutation/launch.
    pub(super) fn unchanged(&self, source: &SourceContext) -> Result<(), NativeError> {
        self.observed()?.require_same(&self.state)?;
        source.unchanged()
    }
}

/// Reads actual primary state only through a retained owned created process, with no write rights.
pub(super) fn read_child(child: &OwnedChild) -> Result<TokenState, NativeError> {
    let mut raw = HANDLE::default();
    // SAFETY: fixed retained owned child process; owned output QUERY|READ_CONTROL only.
    unsafe { OpenProcessToken(child.process.0, TOKEN_QUERY | TOKEN_READ_CONTROL, &mut raw) }
        .map_err(map_native_error)?;
    let handle = OwnedHandle(raw);
    TokenState::read(&handle)
}
