// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native boundary progress is diagnostic evidence only, never acquisition authority.

const PREFIX: &str = "{\"diagnostic\":\"native-acquisition-progress";

/// Retains only an unmatched, complete, closed native boundary in this Rust phase.
#[derive(Default)]
pub(super) struct NativeProgress {
    entered: Option<&'static str>,
    invalid: bool,
}

impl NativeProgress {
    /// Recognizes reserved progress lines; malformed or unbalanced transcripts stay invalid.
    pub(super) fn consume(&mut self, line: &str) -> bool {
        if !line.starts_with(PREFIX) {
            if !line.is_empty() && PREFIX.starts_with(line) {
                self.invalidate();
                return true;
            }
            return false;
        }
        let Some((stage, entering)) = parse(line) else {
            self.invalidate();
            return true;
        };
        if self.invalid {
            return true;
        }
        match (self.entered, entering) {
            (None, true) => self.entered = Some(stage),
            (Some(previous), false) if previous == stage => self.entered = None,
            _ => self.invalidate(),
        }
        true
    }

    /// Discards confidence when parser bounds, malformed text, or partial tails hide ordering.
    pub(super) fn invalidate(&mut self) {
        self.entered = None;
        self.invalid = true;
    }

    /// A fresh Rust phase/READY starts with no historical native progress.
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    /// Names an entered boundary with no observed return at the parent's deadline.
    /// This does not claim that an Apple call returned a timeout status.
    pub(super) fn timeout_stage(&self) -> Option<&'static str> {
        if self.invalid { None } else { self.entered }
    }
}

/// Accepts exactly the fixed C emitter grammar and closed acquisition boundaries.
fn parse(line: &str) -> Option<(&'static str, bool)> {
    let body =
        line.strip_prefix("{\"diagnostic\":\"native-acquisition-progress\",\"substage\":\"")?;
    let (stage, event) = body.split_once("\",\"event\":\"")?;
    let stage = *crate::scsi_worker_startup::NATIVE_STAGES
        .iter()
        .find(|&&candidate| candidate == stage && candidate != "usb-acquire-exception")?;
    match event {
        "enter\"}" => Some((stage, true)),
        "return\"}" => Some((stage, false)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::NativeError;
    use crate::scsi_worker_startup::{StartupDiagnostics, reset, take_last_worker_startup_failure};

    const ACQUIRE: &str =
        "{\"diagnostic\":\"worker-startup\",\"stage\":\"acquire\",\"status\":0}\n";
    const ENTER: &str = "{\"diagnostic\":\"native-acquisition-progress\",\"substage\":\"usb-open-interface\",\"event\":\"enter\"}\n";
    const RETURN: &str = "{\"diagnostic\":\"native-acquisition-progress\",\"substage\":\"usb-open-interface\",\"event\":\"return\"}\n";

    /// Exercises the real bounded startup parser and final failure publication.
    fn failure(records: &[&[u8]], parent: &'static str, error: NativeError) -> &'static str {
        reset();
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(ACQUIRE.as_bytes());
        for record in records {
            observer.consume(record);
        }
        observer.parent_read_failure(parent, error);
        take_last_worker_startup_failure().unwrap().code()
    }

    /// Removing progress refinement must leave this parent timeout too coarse.
    #[test]
    fn native_progress_unmatched_entry_refines_only_acquisition_timeout() {
        assert_eq!(
            failure(&[ENTER.as_bytes()], "init-read", NativeError::TimedOut),
            "candidate-worker-usb-open-interface-timed-out"
        );
        for (parent, error, expected) in [
            (
                "init-read",
                NativeError::TransportUnavailable,
                "candidate-worker-acquire-transport-unavailable",
            ),
            (
                "context-proof",
                NativeError::TimedOut,
                "candidate-worker-context-proof-timed-out",
            ),
            (
                "init-frame",
                NativeError::TimedOut,
                "candidate-worker-init-frame-timed-out",
            ),
            (
                "init-write",
                NativeError::TimedOut,
                "candidate-worker-init-write-timed-out",
            ),
        ] {
            assert_eq!(failure(&[ENTER.as_bytes()], parent, error), expected);
        }
    }

    /// Completed/malformed transcripts must never attribute a stale native boundary.
    #[test]
    fn native_progress_return_and_invalid_transcripts_retain_coarse_timeout() {
        let extra = ENTER.replace("\"event\":\"enter\"", "\"event\":\"enter\",\"secret\":1");
        let unknown = ENTER.replace("usb-open-interface", "unknown");
        let malformed = ENTER.replace("\"event\":\"enter\"", "\"event\":3");
        let mismatch = RETURN.replace("usb-open-interface", "usb-configure-device");
        let mut invalid_utf8 = ENTER.as_bytes().to_vec();
        invalid_utf8.insert(invalid_utf8.len() - 2, 0xff);
        let mut long = ENTER.trim_end().as_bytes().to_vec();
        long.extend_from_slice(&vec![b'x'; 300]);
        long.push(b'\n');
        for transcript in [
            vec![ENTER.as_bytes(), RETURN.as_bytes()],
            vec![ENTER.as_bytes(), ENTER.as_bytes()],
            vec![ENTER.as_bytes(), mismatch.as_bytes()],
            vec![ENTER.as_bytes(), extra.as_bytes()],
            vec![ENTER.as_bytes(), unknown.as_bytes()],
            vec![ENTER.as_bytes(), malformed.as_bytes()],
            vec![
                ENTER.as_bytes(),
                b"{\"diagnostic\":\"native-acquisition-progress\n",
            ],
            vec![
                ENTER.as_bytes(),
                b"{\"diagnostic\":\"native-acquisition-prog\n",
            ],
            vec![ENTER.as_bytes(), &invalid_utf8],
            vec![ENTER.as_bytes(), &long],
            vec![ENTER.as_bytes(), ENTER.trim_end().as_bytes()],
            vec![ENTER.as_bytes(), &[b'\n'; 64]],
            vec![ENTER.as_bytes(), &vec![b'x'; 8193]],
        ] {
            assert_eq!(
                failure(&transcript, "init-read", NativeError::TimedOut),
                "candidate-worker-acquire-timed-out"
            );
        }
    }

    /// New native and Rust phases replace or discard progress without overriding terminal evidence.
    #[test]
    fn native_progress_preserves_existing_completed_failure_precedence() {
        let capture = ENTER.replace("usb-open-interface", "usb-capture-device");
        assert_eq!(
            failure(
                &[ENTER.as_bytes(), RETURN.as_bytes(), capture.as_bytes()],
                "init-read",
                NativeError::TimedOut
            ),
            "candidate-worker-usb-capture-device-timed-out"
        );
        let native = b"{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":3,\"nativeCodeKind\":\"none\",\"nativeCode\":0}\n";
        assert_eq!(
            failure(
                &[ENTER.as_bytes(), native],
                "init-read",
                NativeError::TimedOut
            ),
            "candidate-worker-usb-open-interface-access-denied"
        );
        let fresh = b"{\"diagnostic\":\"interface-init-evidence\",\"status\":10,\"domain\":0,\"code\":0,\"reason\":0,\"underDomain\":0,\"underCode\":0}\n";
        assert_eq!(
            failure(
                &[ENTER.as_bytes(), fresh],
                "init-read",
                NativeError::TimedOut
            ),
            "candidate-worker-usb-interface-fresh-error-missing"
        );
        assert_eq!(
            failure(
                &[ENTER.as_bytes(), ACQUIRE.as_bytes()],
                "init-read",
                NativeError::TimedOut
            ),
            "candidate-worker-acquire-timed-out"
        );
    }

    /// Chunk boundaries cannot erase a complete valid record; READY discards all observations.
    #[test]
    fn native_progress_chunking_and_ready_do_not_publish_stale_failure() {
        assert_eq!(
            failure(
                &[&ENTER.as_bytes()[..35], &ENTER.as_bytes()[35..]],
                "init-read",
                NativeError::TimedOut
            ),
            "candidate-worker-usb-open-interface-timed-out"
        );
        reset();
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(ENTER.as_bytes());
        observer.success();
        observer.parent_read_failure("init-read", NativeError::TimedOut);
        assert!(take_last_worker_startup_failure().is_none());
    }

    /// A completed worker error frame is not the parent's deadline, even without a return marker.
    #[test]
    fn native_progress_completed_child_timeout_does_not_refine_parent_stage() {
        reset();
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(ACQUIRE.as_bytes());
        observer.consume(ENTER.as_bytes());
        observer.failure("init-read", NativeError::TimedOut);
        assert_eq!(
            take_last_worker_startup_failure().unwrap().code(),
            "candidate-worker-acquire-timed-out"
        );
    }

    /// A full bounded native path remains parseable and only its final unmatched entry refines.
    #[test]
    fn native_progress_full_path_stays_within_existing_parser_budget() {
        reset();
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(ACQUIRE.as_bytes());
        for stage in crate::scsi_worker_startup::NATIVE_STAGES {
            if *stage == "usb-acquire-exception" {
                continue;
            }
            for event in ["enter", "return"] {
                observer.consume(format!("{{\"diagnostic\":\"native-acquisition-progress\",\"substage\":\"{stage}\",\"event\":\"{event}\"}}\n").as_bytes());
            }
        }
        observer.consume(ENTER.as_bytes());
        observer.parent_read_failure("init-read", NativeError::TimedOut);
        assert_eq!(
            take_last_worker_startup_failure().unwrap().code(),
            "candidate-worker-usb-open-interface-timed-out"
        );
    }
}
