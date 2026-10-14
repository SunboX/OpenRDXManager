// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exclusive actual-child token DACL experiment; source/derived/borrowed handles cannot reach its setter.
use super::*;
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, SetKernelObjectSecurity, TOKEN_READ_CONTROL, TOKEN_WRITE_DAC,
};

/// Exact creation lineage and private held handles outlive the suspended proof and setter.
pub(super) struct OwnedActualChildToken<'a> {
    child: &'a OwnedChild,
    fixture: &'a Fixture,
    source: &'a SourceContext,
    derived: &'a MinimalDerivedToken,
    deadline: &'a Deadline,
    subject: Subject,
    query_token: OwnedHandle,
    write_token: OwnedHandle,
    before: TokenState,
    process: Components,
    thread: Components,
    expected: Components,
    model: ControlModel,
}
/// Reads only the primary token of this exact returned owned process; never accepts a raw token or PID.
fn open_child_token(child: &OwnedChild, write: bool) -> Result<OwnedHandle, NativeError> {
    let mut raw = HANDLE::default();
    let rights = TOKEN_QUERY
        | TOKEN_READ_CONTROL
        | if write {
            TOKEN_WRITE_DAC
        } else {
            Default::default()
        };
    // SAFETY: returned retained process handle; fixed rights, immediately RAII-owned token output.
    unsafe { OpenProcessToken(child.process.0, rights, &mut raw) }.map_err(map_native_error)?;
    Ok(OwnedHandle(raw))
}
impl<'a> OwnedActualChildToken<'a> {
    /// Full fresh proof precedes the sole extra WRITE_DAC open; unknown/alias is fatal.
    pub(super) fn observe(
        child: &'a OwnedChild,
        fixture: &'a Fixture,
        source: &'a SourceContext,
        derived: &'a MinimalDerivedToken,
        deadline: &'a Deadline,
        subject: Subject,
    ) -> Result<Self, NativeError> {
        source.unchanged()?;
        derived.unchanged(source)?;
        let proof = prove_child_quiet(
            child,
            fixture,
            &source.state.snapshot,
            &source.console,
            source.session,
        );
        output::facts(subject.phase("observe"), &[("fresh-proof", proof.is_ok())]);
        proof?;
        let query_token = open_child_token(child, false)?;
        let before = TokenState::read(&query_token)?;
        let properties = before.snapshot == derived.observed()?.snapshot;
        let source_id = before.identity(&source.state);
        let derived_id = before.identity(&derived.state);
        let known = source_id[0] && derived_id[0];
        output::facts(
            subject.phase("observe"),
            &[
                ("full-properties-known", true),
                ("full-properties-equal", properties),
                ("identities-known", known),
                ("actual-source-distinct", known && !source_id[1]),
                ("actual-derived-distinct", known && !derived_id[1]),
            ],
        );
        if !properties || !known || source_id[1] || derived_id[1] {
            return Err(NativeError::AccessDenied);
        }
        let process = PrivateDescriptor::read(child.process.0)?.components;
        let thread = PrivateDescriptor::read(child.thread.0)?.components;
        // Reproof is repeated immediately BEFORE requesting any write permission.
        source.unchanged()?;
        derived.unchanged(source)?;
        prove_child_quiet(
            child,
            fixture,
            &source.state.snapshot,
            &source.console,
            source.session,
        )?;
        deadline.require_launch()?;
        let write_token = open_child_token(child, true)?;
        let written = TokenState::read(&write_token)?;
        let same = written.identity(&before);
        let prewrite = written.preservation(&before).iter().all(|v| *v);
        output::facts(
            subject.phase("observe"),
            &[
                ("write-handle-same-instance", same[0] && same[1]),
                ("prewrite-state-exact", prewrite),
                ("source-unchanged", source.unchanged().is_ok()),
                ("derived-unchanged", derived.unchanged(source).is_ok()),
            ],
        );
        written.require_same(&before)?;
        let expected = before
            .descriptor
            .with_user_allow(source.user.bytes(), ObjectRole::Token)
            .map_err(|_| NativeError::Other)?;
        source.unchanged()?;
        derived.unchanged(source)?;
        Ok(Self {
            child,
            fixture,
            source,
            derived,
            deadline,
            subject,
            query_token,
            write_token,
            before,
            process,
            thread,
            expected,
            model: ControlModel::suspended(),
        })
    }
    /// Revalidates the same held/current primary instance plus EVERY prewrite component/property.
    fn before_write(&self) -> Result<Admission, NativeError> {
        self.source.unchanged()?;
        self.derived.unchanged(self.source)?;
        let held = TokenState::read(&self.write_token)?;
        held.require_same(&self.before)?;
        TokenState::read(&self.query_token)?.require_same(&self.before)?;
        let current = open_child_token(self.child, false)?;
        let current = TokenState::read(&current)?;
        current.require_same(&self.before)?;
        if PrivateDescriptor::read(self.child.process.0)?.components != self.process
            || PrivateDescriptor::read(self.child.thread.0)?.components != self.thread
        {
            return Err(NativeError::AccessDenied);
        }
        prove_child_quiet(
            self.child,
            self.fixture,
            &self.source.state.snapshot,
            &self.source.console,
            self.source.session,
        )?;
        // Refresh current PRIMARY instance/full state AFTER all prior queries/proof; held setter is never retargeted.
        let last = open_child_token(self.child, false)?;
        let last = TokenState::read(&last)?;
        last.require_same(&self.before)?;
        let same = last.identity(&held);
        let source = last.identity(&self.source.state);
        let derived = last.identity(&self.derived.state);
        Ok(Admission {
            fresh: true,
            image: true,
            console: true,
            properties: true,
            identities_known: same[0] && source[0] && derived[0],
            same_held: same[1],
            source_alias: source[1],
            derived_alias: derived[1],
            epoch_fresh: true,
            remaining_ms: self.deadline.remaining(),
        })
    }
    /// Exactly one fixed noninherit SDK USER ACE is set on this factory-held actual token ONLY.
    pub(super) fn add_fixed_user_allow(&mut self) -> Result<(), NativeError> {
        if TOKEN_ALL_ACCESS.0 != 0x000f_01ff {
            return Err(NativeError::UnsupportedPlatform);
        }
        let storage =
            PrivateDescriptor::from_bytes(&self.expected.bytes().map_err(|_| NativeError::Other)?)?;
        self.model.invalidate();
        let admission = self.before_write()?;
        let ticket = self
            .model
            .prepare(admission)
            .map_err(|_| NativeError::AccessDenied)?;
        self.model
            .authorize_write(ticket)
            .map_err(|_| NativeError::AccessDenied)?;
        // No metadata/output callback intervenes after fresh epoch admission. No token-property setter.
        // https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
        // SAFETY: known nonalias factory-owned actual token; fixed DACL-only information, aligned live storage.
        unsafe {
            SetKernelObjectSecurity(
                self.write_token.0,
                DACL_SECURITY_INFORMATION,
                storage.pointer(),
            )
        }
        .map_err(map_native_error)?;
        output::facts(
            self.subject.phase("write"),
            &[("epoch-fresh", true), ("write-succeeded", true)],
        );
        Ok(())
    }
    /// Every component is separately observed before exact failure; no profile fact substitutes for equality.
    pub(super) fn require_exact_readback(&self) -> Result<(), NativeError> {
        let current =
            open_child_token(self.child, false).and_then(|handle| TokenState::read(&handle));
        output::facts(
            self.subject.phase("readback"),
            &[("query-ok", current.is_ok())],
        );
        let current = current?;
        let profile = token_acl_profile::observe(
            &current.descriptor,
            &self.before.descriptor,
            &self.expected,
            self.source.user.bytes(),
        )
        .map_err(|_| NativeError::EvidenceIncomplete)?;
        let ids = current.identity(&self.before);
        let same = ids[0] && ids[1];
        let process = PrivateDescriptor::read(self.child.process.0)?.components == self.process;
        let thread = PrivateDescriptor::read(self.child.thread.0)?.components == self.thread;
        let exact = current.descriptor == self.expected;
        let properties = current.snapshot == self.before.snapshot;
        let default = current.default == self.before.default;
        let source = self.source.unchanged();
        let derived = self.derived.unchanged(self.source);
        let kept = current.descriptor.preservation(&self.before.descriptor);
        output::facts(
            self.subject.phase("readback"),
            &[
                ("token-dacl-exact", exact),
                ("one-addition", profile.one_addition),
                ("old-aces-retained", profile.old_aces),
                ("denials-equal", profile.denials),
                ("owner-preserved", kept[0]),
                ("group-preserved", kept[1]),
                ("label-preserved", kept[2]),
                ("control-preserved", kept[3]),
                ("same-instance", same),
                ("full-properties-equal", properties),
                ("default-dacl-equal", default),
                ("process-exact", process),
                ("thread-exact", thread),
                ("source-unchanged", source.is_ok()),
                ("derived-unchanged", derived.is_ok()),
            ],
        );
        let isolated = protocol::isolation(&protocol::Isolation {
            exact,
            addition: profile.one_addition,
            old_aces: profile.old_aces,
            denials: profile.denials,
            kept,
            same_instance: same,
            properties,
            default,
            process,
            thread,
            source: source.is_ok(),
            derived: derived.is_ok(),
        });
        source?;
        derived?;
        if !isolated {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    }
    /// Quiet strict readback repeats without duplicate output just before inseparable last proof/resume.
    fn quiet_readback(&self) -> Result<(), NativeError> {
        let current = open_child_token(self.child, false)?;
        let current = TokenState::read(&current)?;
        let id = current.identity(&self.before);
        let held = TokenState::read(&self.write_token)?;
        let same = current.identity(&held);
        if !(id[0]
            && id[1]
            && same[0]
            && same[1]
            && current.descriptor == self.expected
            && held.descriptor == self.expected
            && current.snapshot == self.before.snapshot
            && held.snapshot == self.before.snapshot
            && current.default == self.before.default
            && held.default == self.before.default)
        {
            return Err(NativeError::AccessDenied);
        }
        if PrivateDescriptor::read(self.child.process.0)?.components != self.process
            || PrivateDescriptor::read(self.child.thread.0)?.components != self.thread
        {
            return Err(NativeError::AccessDenied);
        }
        self.source.unchanged()?;
        self.derived.unchanged(self.source)
    }
    /// Last fresh proof and actual resume occur in this one private scope, with no observer/output gap.
    pub(super) fn resume_verified(&mut self) -> Result<(), NativeError> {
        self.deadline.require_launch()?;
        self.quiet_readback()?;
        self.deadline.require_launch()?;
        self.model
            .authorize_resume(true, true)
            .map_err(|_| NativeError::AccessDenied)?;
        prove_child_quiet(
            self.child,
            self.fixture,
            &self.source.state.snapshot,
            &self.source.console,
            self.source.session,
        )?;
        self.child.resume()
    }
}
