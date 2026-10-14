// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in elevated SOURCE control, separate from ordinary Manager/medium child authority.
use super::*;

/// Reconstructs only fixed compiled keys and booleans; no identities/token buffers are emitted.
fn facts(values: &[(&'static str, bool)]) {
    let fields = values
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    println!("openrdx-token-source-control {}", fields.join(" "));
}

/// Fixed phase and fieldless error preserve the primary failure independently of cleanup.
fn checkpoint<T>(
    phase: &'static str,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    println!("openrdx-token-source-control-stage phase={phase} status=begin");
    let result = operation();
    match &result {
        Ok(_) => println!("openrdx-token-source-control-stage phase={phase} status=ok"),
        Err(error) => println!(
            "openrdx-token-source-control-stage phase={phase} status=failed reason={error:?}"
        ),
    }
    result
}

/// Reports private per-property equality before requiring exact complete kernel snapshot equality.
fn snapshot_fields(actual: &SourceSnapshot, source: &SourceSnapshot) {
    facts(&[
        ("child-user-match", actual.user == source.user),
        ("child-session-match", actual.session == source.session),
        (
            "child-elevation-match",
            actual.elevation == source.elevation,
        ),
        (
            "child-integrity-match",
            actual.integrity == source.integrity,
        ),
        (
            "child-ui-access-match",
            actual.ui_access == source.ui_access,
        ),
        (
            "child-sandbox-inert-match",
            actual.sandbox_inert == source.sandbox_inert,
        ),
        ("child-type-match", actual.token_type == source.token_type),
        (
            "child-elevation-type-match",
            actual.elevation_type == source.elevation_type,
        ),
        ("child-groups-match", actual.groups == source.groups),
        (
            "child-privileges-match",
            actual.privileges == source.privileges,
        ),
    ]);
}

/// Only a query token from the retained owned child is read; no supplied PID or external process.
fn prove_source(
    child: &OwnedChild,
    fixture: &Fixture,
    original: &SourceSnapshot,
    console: &OwnedSid,
    session: u32,
) -> Result<(), NativeError> {
    prove_image(child, fixture)?;
    facts(&[("child-image-match", true)]);
    let mut handle = HANDLE::default();
    // SAFETY: retained trusted creation handle; output owns only TOKEN_QUERY access.
    unsafe { OpenProcessToken(child.process.0, TOKEN_QUERY, &mut handle) }
        .map_err(map_native_error)?;
    let token = OwnedHandle(handle);
    let actual = SourceSnapshot::read(&token)?;
    snapshot_fields(&actual, original);
    let matches = actual == *original;
    facts(&[("child-source-snapshot-match", matches)]);
    if !matches {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: bounded read-only active-console/principal revalidation, no account/session changes.
    let live = session == unsafe { WTSGetActiveConsoleSessionId() }
        && console.bytes() == console_sid(session)?.bytes();
    facts(&[("console-revalidated", live)]);
    if !live {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

/// Observes equality after each fixed operation; CPAsUser temporary privilege changes are not assumed away.
fn source_unchanged(
    source: &OwnedHandle,
    original: &SourceSnapshot,
    tag: &'static str,
    query_tag: &'static str,
) -> Result<(), NativeError> {
    let actual = SourceSnapshot::read(source);
    let same = actual.as_ref().is_ok_and(|value| value == original);
    facts(&[(query_tag, actual.is_ok()), (tag, same)]);
    if !same {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

/// Owns one fixed Wait PE control and reaps only its returned process/thread handles on all paths.
fn observe_source_control() -> Result<(), NativeError> {
    let source = checkpoint("source-open", || {
        let mut handle = HANDLE::default();
        // SAFETY: own source primary token; only QUERY/DUPLICATE/ASSIGN_PRIMARY, no adjustment right.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut handle,
            )
        }
        .map_err(map_native_error)?;
        Ok(OwnedHandle(handle))
    })?;
    facts(&[("source-open", true)]);
    let original = checkpoint("source-query", || SourceSnapshot::read(&source))?;
    let (session, console) = checkpoint("console", || {
        // SAFETY: fixed read-only console query.
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err(NativeError::AccessDenied);
        }
        let console = console_sid(session)?;
        let matches = original.user == console.bytes() && original.session == session;
        let high_primary =
            original.elevation != 0 && original.integrity == 0x3000 && original.token_type == 1;
        facts(&[
            ("source-query-ok", true),
            ("source-console-match", matches),
            ("source-high-primary", high_primary),
        ]);
        if !matches || !high_primary {
            return Err(NativeError::AccessDenied);
        }
        Ok((session, console))
    })?;
    let administrator = token_user_sid(&source)?;
    let mut fixture = checkpoint("fixture", || Fixture::create(&administrator, Variant::Wait))?;
    facts(&[("fixture-protected", true)]);
    let mut child = None;
    let mut created = false;
    let primary = (|| {
        child = Some(checkpoint("create", || {
            OwnedChild::create(&fixture, &source)
        })?);
        created = true;
        facts(&[("child-created", true)]);
        checkpoint("source-after-create", || {
            source_unchanged(
                &source,
                &original,
                "source-unchanged-after-create",
                "source-after-create-query-ok",
            )
        })?;
        let owned = child.as_mut().ok_or(NativeError::Other)?;
        checkpoint("proof", || {
            prove_source(owned, &fixture, &original, &console, session)
        })?;
        checkpoint("source-before-resume", || {
            source_unchanged(
                &source,
                &original,
                "source-unchanged-before-resume",
                "source-before-resume-query-ok",
            )
        })?;
        checkpoint("resume", || owned.resume())?;
        facts(&[("child-resumed", true)]);
        checkpoint("wait", || {
            let exit = owned.wait(10_000)?;
            if let Some(code) = exit {
                println!(
                    "openrdx-token-source-control-exit category={}",
                    exit_status::category(code)
                );
            }
            let expected = exit == Some(exit_status::SelfCheckFailure::Elevation as u32);
            facts(&[
                ("child-exited", exit.is_some()),
                ("child-self-elevation-refused", expected),
            ]);
            if !expected {
                return Err(NativeError::Other);
            }
            Ok(())
        })?;
        checkpoint("source-after-exit", || {
            source_unchanged(
                &source,
                &original,
                "source-unchanged-after-exit",
                "source-after-exit-query-ok",
            )
        })
    })();
    // Cleanup never overwrites a primary error. Retained owned creation handles are the only kill targets.
    let reaped = checkpoint("reap", || match child.take() {
        Some(mut child) => child.terminate_and_reap(),
        None => Ok(()),
    });
    let cleaned = checkpoint("cleanup", || fixture.cleanup());
    let unchanged = checkpoint("source-after-cleanup", || {
        source_unchanged(
            &source,
            &original,
            "source-unchanged-after-cleanup",
            "source-after-cleanup-query-ok",
        )
    });
    facts(&[
        ("owned-child-reaped", created && reaped.is_ok()),
        ("fixture-cleaned", cleaned.is_ok()),
    ]);
    primary?;
    reaped?;
    cleaned?;
    unchanged
}

/// Separate privileged control cannot admit any ordinary Manager or satisfy the medium-child gate.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_source_context_child_control() {
    let result = observe_source_control();
    assert!(result.is_ok(), "source-control-failed");
}
