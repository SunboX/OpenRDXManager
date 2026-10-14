// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Optional one-object process DACL isolation; never production authorization or a fallback.
use super::*;
#[path = "process_descriptor.rs"]
mod process_descriptor;
use process_descriptor::Components;
use windows::Win32::Security::{
    GetKernelObjectSecurity, IsValidSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_DEFAULT_DACL, TOKEN_READ_CONTROL, TokenDefaultDacl,
};
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

/// Private aligned descriptor and canonical components; identities never implement Debug.
struct PrivateDescriptor {
    storage: Vec<usize>,
    components: Components,
}
impl PrivateDescriptor {
    /// Owns bounded aligned bytes only after the complete pure component parser succeeds.
    fn from_bytes(bytes: &[u8]) -> Result<Self, NativeError> {
        let components = Components::parse(bytes).map_err(|_| NativeError::Other)?;
        let mut storage = vec![0_usize; bytes.len().div_ceil(size_of::<usize>())];
        // SAFETY: initialized bytes fit the allocated aligned buffer; pure parser bounds every component.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), storage.as_mut_ptr().cast(), bytes.len())
        };
        let descriptor = Self {
            storage,
            components,
        };
        // SAFETY: all ordinary ACE/SID/LABEL extents have been validated before native descriptor validation.
        if !unsafe { IsValidSecurityDescriptor(descriptor.pointer()).as_bool() } {
            return Err(NativeError::Other);
        }
        Ok(descriptor)
    }

    /// Returns only a pointer into this private live aligned descriptor, never a kernel object to write.
    fn pointer(&self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR(self.storage.as_ptr().cast_mut().cast())
    }

    /// Reads owner/group/DACL plus LABEL only from an exact retained owned child handle.
    fn read(handle: HANDLE) -> Result<Self, NativeError> {
        let mut needed = 0;
        let information = 1 | 2 | 4 | 0x10;
        // SAFETY: retained owned handle, LABEL-only rather than full SACL; sizing output only.
        let sizing = unsafe { GetKernelObjectSecurity(handle, information, None, 0, &mut needed) };
        if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
            || !(20..=MAX_PROBE_BYTES).contains(&(needed as usize))
        {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = storage.len() * size_of::<usize>();
        // SAFETY: initialized aligned bounded output; exact held object, read-only security information.
        unsafe {
            GetKernelObjectSecurity(
                handle,
                information,
                Some(PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast())),
                capacity as u32,
                &mut needed,
            )
        }
        .map_err(map_native_error)?;
        if !(20..=capacity).contains(&(needed as usize)) {
            return Err(NativeError::Other);
        }
        // SAFETY: API initialized the checked returned extent; no bytes/identities leave the process.
        let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast(), needed as usize) };
        Self::from_bytes(bytes)
    }
}

/// Private canonical process/thread/primary-token readbacks for exact one-object comparison.
struct Objects {
    process: PrivateDescriptor,
    thread: PrivateDescriptor,
    token: PrivateDescriptor,
}
impl Objects {
    /// Reads only trusted created process/thread handles and a separate owned query-token opening.
    fn read(child: &OwnedChild) -> Result<Self, NativeError> {
        let mut handle = HANDLE::default();
        // SAFETY: exact retained owned child process, query/security read only; no arbitrary PID.
        unsafe {
            OpenProcessToken(
                child.process.0,
                TOKEN_QUERY | TOKEN_READ_CONTROL,
                &mut handle,
            )
        }
        .map_err(map_native_error)?;
        let token = OwnedHandle(handle);
        Ok(Self {
            process: PrivateDescriptor::read(child.process.0)?,
            thread: PrivateDescriptor::read(child.thread.0)?,
            token: PrivateDescriptor::read(token.0)?,
        })
    }

    /// Requires the exact expected DACL, all other process components and thread/token components unchanged.
    fn isolate(
        &self,
        baseline: &Self,
        expected: &Components,
        prefix: &'static str,
    ) -> Result<(), NativeError> {
        let process = self.process.components == *expected;
        let other = self
            .process
            .components
            .same_other_components(&baseline.process.components);
        let thread = self.thread.components == baseline.thread.components;
        let token = self.token.components == baseline.token.components;
        let kept = self
            .process
            .components
            .preservation(&baseline.process.components);
        println!(
            "openrdx-token-process-dacl-control {prefix}-process-owner-preserved={} {prefix}-process-group-preserved={} {prefix}-process-label-preserved={} {prefix}-process-control-preserved={} {prefix}-thread-components-exact={thread} {prefix}-token-components-exact={token}",
            kept[0], kept[1], kept[2], kept[3]
        );
        if prefix == "treatment" {
            facts(&[
                ("treatment-process-dacl-exact", process),
                ("treatment-other-components-unchanged", other),
                ("treatment-thread-unchanged", thread),
                ("treatment-token-unchanged", token),
            ]);
        } else {
            facts(&[
                (
                    "positive-descriptors-proved",
                    process && other && thread && token,
                ),
                ("positive-process-dacl-exact", process),
            ]);
        }
        if !(process && other && thread && token) {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }
}

/// Snapshots nullable source default DACL bytes privately without changing token/object security.
fn source_default_dacl(source: &OwnedHandle) -> Result<Option<Vec<u8>>, NativeError> {
    let buffer = TokenBuffer::read(source, TokenDefaultDacl)?;
    let header = buffer.header::<TOKEN_DEFAULT_DACL>()?;
    if header.DefaultDacl.is_null() {
        return Ok(None);
    }
    let offset = (header.DefaultDacl as usize)
        .checked_sub(buffer.storage.as_ptr() as usize)
        .filter(|offset| {
            *offset >= size_of::<TOKEN_DEFAULT_DACL>()
                && *offset % 4 == 0
                && offset
                    .checked_add(8)
                    .is_some_and(|end| end <= buffer.length)
        })
        .ok_or(NativeError::Other)?;
    // SAFETY: bounded initialized token bytes; extent and ordinary ACE/SID table validated below.
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.storage.as_ptr().cast::<u8>(), buffer.length) };
    let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= buffer.length)
        .ok_or(NativeError::Other)?;
    let acl = &bytes[offset..end];
    process_descriptor::validate_default_acl(acl).map_err(|_| NativeError::Other)?;
    Ok(Some(acl.to_vec()))
}

/// Emits only compiled boolean keys, never descriptor/status/identity bytes.
fn facts(values: &[(&'static str, bool)]) {
    println!(
        "openrdx-token-process-dacl-control {}",
        values
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

/// Preserves exact native result with closed stage vocabulary independently of later cleanup.
fn checkpoint<T>(
    phase: &'static str,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    println!("openrdx-token-process-dacl-control-stage phase={phase} status=begin");
    let result = operation();
    match &result {
        Ok(_) => println!("openrdx-token-process-dacl-control-stage phase={phase} status=ok"),
        Err(error) => println!(
            "openrdx-token-process-dacl-control-stage phase={phase} status=failed reason={error:?}"
        ),
    }
    result
}

/// Exact source/default-DACL snapshots remain identical before every Resume and after cleanup.
fn source_unchanged(
    source: &OwnedHandle,
    original: &SourceSnapshot,
    dacl: &Option<Vec<u8>>,
    prefix: &'static str,
) -> Result<(), NativeError> {
    let snapshot = SourceSnapshot::read(source);
    let default = source_default_dacl(source);
    let same_snapshot = snapshot.as_ref().is_ok_and(|value| value == original);
    let same_default = default.as_ref().is_ok_and(|value| value == dacl);
    let tag = if prefix == "final" {
        String::new()
    } else {
        format!("{prefix}-")
    };
    println!(
        "openrdx-token-process-dacl-control {tag}source-snapshot-query-ok={} {tag}source-snapshot-unchanged={same_snapshot} {tag}source-default-dacl-query-ok={} {tag}source-default-dacl-unchanged={same_default}",
        snapshot.is_ok(),
        default.is_ok()
    );
    snapshot?;
    default?;
    if !same_snapshot || !same_default {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

/// Defines correctly sized process-only noninheriting attributes over a private live descriptor.
fn attributes(descriptor: &PrivateDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.pointer().0,
        bInheritHandle: false.into(),
    }
}

/// Executes matched untreated/treatment Wait PE and an independent fixed positive PE; owns all cleanup.
fn observe_control() -> Result<(), NativeError> {
    let (source, original, console, session, dacl, derived, user) = checkpoint("setup", || {
        let mut handle = HANDLE::default();
        // SAFETY: own source handle; later label reduction applies to a fresh derived token only.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
                &mut handle,
            )
        }
        .map_err(map_native_error)?;
        let source = OwnedHandle(handle);
        let original = SourceSnapshot::read(&source)?;
        // SAFETY: read-only console query; no session/account modifications.
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err(NativeError::AccessDenied);
        }
        let console = console_sid(session)?;
        if original.user != console.bytes()
            || original.session != session
            || original.elevation == 0
            || original.integrity != 0x3000
            || original.token_type != 1
        {
            return Err(NativeError::AccessDenied);
        }
        let dacl = source_default_dacl(&source)?;
        let user = token_user_sid(&source)?;
        let mut handle = HANDLE::default();
        // SAFETY: standard approved fresh reduction only, identical to untreated ordinary setup.
        unsafe {
            CreateRestrictedToken(
                source.0,
                LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
                None,
                None,
                None,
                &mut handle,
            )
        }
        .map_err(map_native_error)?;
        let derived = OwnedHandle(handle);
        set_medium(&derived)?;
        negative_predicates(&original, &derived, &console, session)?;
        facts(&[("source-verified", true), ("derived-verified", true)]);
        Ok((source, original, console, session, dacl, derived, user))
    })?;
    let mut wait_fixture = checkpoint("fixture", || Fixture::create(&user, Variant::Wait))?;
    let mut positive_fixture = None;
    let mut children = Vec::new();
    let primary = (|| {
        children.push(checkpoint("baseline-create", || {
            OwnedChild::create(&wait_fixture, &derived)
        })?);
        let baseline = checkpoint("baseline-proof", || {
            let child = children.last().ok_or(NativeError::Other)?;
            prove_child_quiet(child, &wait_fixture, &original, &console, session)?;
            let objects = Objects::read(child);
            facts(&[("baseline-descriptors-query-ok", objects.is_ok())]);
            let objects = objects?;
            facts(&[
                ("baseline-image-proved", true),
                ("baseline-descriptors-valid", true),
            ]);
            Ok(objects)
        })?;
        checkpoint("baseline-resume", || {
            source_unchanged(&source, &original, &dacl, "baseline")?;
            prove_child_quiet(
                children.last().ok_or(NativeError::Other)?,
                &wait_fixture,
                &original,
                &console,
                session,
            )?;
            children.last().ok_or(NativeError::Other)?.resume()
        })?;
        checkpoint("baseline-wait", || {
            let exit = children
                .last_mut()
                .ok_or(NativeError::Other)?
                .wait(10_000)?;
            if let Some(code) = exit {
                println!(
                    "openrdx-token-process-dacl-control-exit phase=baseline-wait category={}",
                    exit_status::category(code)
                );
            }
            let expected = exit == Some(0xC000_0142);
            facts(&[("baseline-dll-init-failed", expected)]);
            if !expected {
                return Err(NativeError::Other);
            }
            Ok(())
        })?;
        checkpoint("baseline-reap", || {
            children
                .last_mut()
                .ok_or(NativeError::Other)?
                .terminate_and_reap()
        })?;
        children.pop();
        facts(&[("baseline-reaped", true)]);
        let (expected, descriptor) = checkpoint("descriptor", || {
            let expected = baseline
                .process
                .components
                .with_user_process_allow(user.bytes(), PROCESS_ALL_ACCESS.0)
                .map_err(|_| NativeError::Other)?;
            let descriptor =
                PrivateDescriptor::from_bytes(&expected.bytes().map_err(|_| NativeError::Other)?)?;
            facts(&[("process-descriptor-built", true)]);
            Ok((expected, descriptor))
        })?;
        let attributes = attributes(&descriptor);
        children.push(checkpoint("treatment-create", || {
            OwnedChild::create_with_process_security(&wait_fixture, &derived, Some(&attributes))
        })?);
        checkpoint("treatment-proof", || {
            let child = children.last().ok_or(NativeError::Other)?;
            let objects = Objects::read(child);
            facts(&[("treatment-descriptors-query-ok", objects.is_ok())]);
            objects?.isolate(&baseline, &expected, "treatment")?;
            source_unchanged(&source, &original, &dacl, "treatment")?;
            prove_child_quiet(child, &wait_fixture, &original, &console, session)?;
            facts(&[
                ("treatment-image-proved", true),
                ("treatment-token-proved", true),
                ("treatment-console-proved", true),
            ]);
            Ok(())
        })?;
        checkpoint("treatment-resume", || {
            prove_child_quiet(
                children.last().ok_or(NativeError::Other)?,
                &wait_fixture,
                &original,
                &console,
                session,
            )?;
            children.last().ok_or(NativeError::Other)?.resume()
        })?;
        checkpoint("treatment-wait", || {
            let exit = children.last_mut().ok_or(NativeError::Other)?.wait(100)?;
            if let Some(code) = exit {
                println!(
                    "openrdx-token-process-dacl-control-exit phase=treatment-wait category={}",
                    exit_status::category(code)
                );
            }
            facts(&[("treatment-timeout-alive", exit.is_none())]);
            if exit.is_some() {
                return Err(NativeError::Other);
            }
            Ok(())
        })?;
        checkpoint("treatment-reap", || {
            children
                .last_mut()
                .ok_or(NativeError::Other)?
                .terminate_and_reap()
        })?;
        children.pop();
        facts(&[("treatment-reaped", true)]);
        positive_fixture = Some(checkpoint("positive-fixture", || {
            Fixture::create(&user, Variant::Proof)
        })?);
        let fixture = positive_fixture.as_ref().ok_or(NativeError::Other)?;
        children.push(checkpoint("positive-create", || {
            OwnedChild::create_with_process_security(fixture, &derived, Some(&attributes))
        })?);
        checkpoint("positive-proof", || {
            let child = children.last().ok_or(NativeError::Other)?;
            let objects = Objects::read(child);
            facts(&[("positive-descriptors-query-ok", objects.is_ok())]);
            objects?.isolate(&baseline, &expected, "positive")?;
            source_unchanged(&source, &original, &dacl, "positive")?;
            prove_child_quiet(child, fixture, &original, &console, session)?;
            facts(&[
                ("positive-image-proved", true),
                ("positive-token-proved", true),
                ("positive-console-proved", true),
            ]);
            Ok(())
        })?;
        checkpoint("positive-resume", || {
            prove_child_quiet(
                children.last().ok_or(NativeError::Other)?,
                fixture,
                &original,
                &console,
                session,
            )?;
            children.last().ok_or(NativeError::Other)?.resume()
        })?;
        checkpoint("positive-wait", || {
            let exit = children
                .last_mut()
                .ok_or(NativeError::Other)?
                .wait(10_000)?;
            if let Some(code) = exit {
                println!(
                    "openrdx-token-process-dacl-control-exit phase=positive-wait category={}",
                    exit_status::category(code)
                );
            }
            facts(&[("positive-exit-zero", exit == Some(0))]);
            if exit != Some(0) {
                return Err(NativeError::Other);
            }
            Ok(())
        })?;
        checkpoint("positive-reap", || {
            children
                .last_mut()
                .ok_or(NativeError::Other)?
                .terminate_and_reap()
        })?;
        children.pop();
        facts(&[("positive-reaped", true)]);
        Ok(())
    })();
    let child_cleanup = checkpoint("child-cleanup", || {
        let mut result = Ok(());
        for child in &mut children {
            if let Err(error) = child.terminate_and_reap() {
                if result.is_ok() {
                    result = Err(error);
                }
            }
        }
        children.clear();
        facts(&[("owned-children-cleanup-ok", result.is_ok())]);
        result
    });
    let positive_cleanup = checkpoint("positive-fixture-cleanup", || {
        let result = match positive_fixture.as_mut() {
            Some(fixture) => fixture.cleanup(),
            None => Ok(()),
        };
        facts(&[("positive-fixture-cleanup-ok", result.is_ok())]);
        result
    });
    let wait_cleanup = checkpoint("wait-fixture-cleanup", || {
        let result = wait_fixture.cleanup();
        facts(&[("wait-fixture-cleanup-ok", result.is_ok())]);
        result
    });
    let cleanup = checkpoint("cleanup", || {
        let result = child_cleanup.and(positive_cleanup).and(wait_cleanup);
        facts(&[("fixtures-cleaned", result.is_ok())]);
        result
    });
    let unchanged = checkpoint("source-check", || {
        source_unchanged(&source, &original, &dacl, "final")
    });
    primary?;
    cleanup?;
    unchanged
}

/// Optional exact one-object control never clears the fatal unchanged medium-child verification gate.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_process_dacl_child_control() {
    assert!(observe_control().is_ok(), "process-dacl-control-failed");
}
