// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed, non-authorizing observations of the existing admission proof sequence.

use crate::NativeError;

/// Closed initial endpoint proof phases, independent of peer data or policy text.
pub(crate) enum AdmissionPhase {
    RuntimeCapture,
    PeerBeforeRuntime,
    FullRuntime,
    PeerAfterRuntime,
}

impl AdmissionPhase {
    /// Returns fixed start, success, and failure labels without formatting peer information.
    fn labels(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::RuntimeCapture => (
                "session-runtime-verification-start",
                "session-runtime-verification-ok",
                "session-runtime-verification-failed",
            ),
            Self::PeerBeforeRuntime => (
                "session-peer-before-runtime-start",
                "session-peer-before-runtime-ok",
                "session-peer-before-runtime-failed",
            ),
            Self::FullRuntime => (
                "session-full-runtime-start",
                "session-full-runtime-ok",
                "session-full-runtime-failed",
            ),
            Self::PeerAfterRuntime => (
                "session-peer-after-runtime-start",
                "session-peer-after-runtime-ok",
                "session-peer-after-runtime-failed",
            ),
        }
    }
}

/// Observes one operation exactly once without changing its successful value or error.
pub(crate) fn observe_phase<T>(
    phase: AdmissionPhase,
    operation: impl FnOnce() -> Result<T, NativeError>,
    observe: &mut impl FnMut(&'static str, Option<NativeError>),
) -> Result<T, NativeError> {
    let (start, success, failure) = phase.labels();
    observe(start, None);
    let result = operation();
    match &result {
        Ok(_) => observe(success, None),
        Err(error) => observe(failure, Some(*error)),
    }
    result
}

/// Retains both fresh peer proofs around the complete runtime proof and stops at the first error.
/// The ordinary worker path supplies a no-op observer; only initial endpoint admission logs.
pub(crate) fn revalidate_peer_runtime(
    mut peer: impl FnMut() -> Result<(), NativeError>,
    runtime: impl FnOnce() -> Result<(), NativeError>,
    observe: &mut impl FnMut(&'static str, Option<NativeError>),
) -> Result<(), NativeError> {
    observe_phase(AdmissionPhase::PeerBeforeRuntime, &mut peer, observe)?;
    observe_phase(AdmissionPhase::FullRuntime, runtime, observe)?;
    observe_phase(AdmissionPhase::PeerAfterRuntime, peer, observe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Missing phase observations, reordered or reused proofs, and swallowed errors must fail.
    #[test]
    fn admission_diagnostics_observe_each_fresh_proof_and_stop_on_exact_failure() {
        for failure_at in [None, Some(0), Some(1), Some(2)] {
            let trace = RefCell::new(Vec::new());
            let next_proof = std::cell::Cell::new(0);
            let proof = || {
                let index = next_proof.get();
                next_proof.set(index + 1);
                trace.borrow_mut().push(format!("proof-{index}"));
                if failure_at == Some(index) {
                    Err(crate::NativeError::EvidenceIncomplete)
                } else {
                    Ok(())
                }
            };
            let outcome = revalidate_peer_runtime(proof, proof, &mut |phase, error| {
                trace.borrow_mut().push(format!("{phase}:{error:?}"));
            });
            let mut expected = Vec::new();
            for (index, phase) in [
                "session-peer-before-runtime",
                "session-full-runtime",
                "session-peer-after-runtime",
            ]
            .iter()
            .enumerate()
            {
                expected.push(format!("{phase}-start:None"));
                expected.push(format!("proof-{index}"));
                if failure_at == Some(index) {
                    expected.push(format!("{phase}-failed:Some(EvidenceIncomplete)"));
                    break;
                }
                expected.push(format!("{phase}-ok:None"));
            }
            assert_eq!(*trace.borrow(), expected);
            assert_eq!(
                outcome,
                failure_at.map_or(Ok(()), |_| Err(crate::NativeError::EvidenceIncomplete))
            );
        }
    }

    /// Observation retains the operation's exact successful value and sanitized failure.
    #[test]
    fn runtime_capture_diagnostics_preserve_result_and_closed_labels() {
        let mut trace = Vec::new();
        let value = observe_phase(
            AdmissionPhase::RuntimeCapture,
            || Ok(17),
            &mut |phase, error| trace.push((phase, error)),
        );
        assert_eq!(value, Ok(17));
        assert_eq!(
            trace,
            [
                ("session-runtime-verification-start", None),
                ("session-runtime-verification-ok", None)
            ]
        );
        trace.clear();
        let value: Result<(), _> = observe_phase(
            AdmissionPhase::RuntimeCapture,
            || Err(crate::NativeError::AccessDenied),
            &mut |phase, error| trace.push((phase, error)),
        );
        assert_eq!(value, Err(crate::NativeError::AccessDenied));
        assert_eq!(
            trace,
            [
                ("session-runtime-verification-start", None),
                (
                    "session-runtime-verification-failed",
                    Some(crate::NativeError::AccessDenied)
                )
            ]
        );
    }
}
