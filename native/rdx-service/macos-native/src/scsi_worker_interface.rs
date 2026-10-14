// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed interface-init diagnostics, independent of acquisition results or policy.

use crate::scsi_worker_startup::Bucket;

/// Refines diagnostic text only for an unclassified interface-init error, never native results.
///
/// The C branch reports the IOUSBHost NSError contract (SDK: NSError codes are IOReturn).
/// This is not a general NSError/HRESULT/IOKit-family classifier. C currently reuses its
/// NSError variable across successful calls in this legacy record. Fresh constructor records
/// take precedence when available, so this legacy classifier records observed numeric evidence,
/// not proof that the current interface failed for this cause. It never triggers retry,
/// rematching, authorization, capture or commands; unknown/out-of-range values stay Other.
pub(super) fn interface_error_class(
    stage: &str,
    original: Bucket,
    kind: u8,
    native_code: i64,
) -> Bucket {
    if stage != "usb-open-interface" || original != Bucket::Other {
        return original;
    }
    if kind == 0 && native_code == 0 {
        return Bucket::ErrorMissing;
    }
    if kind != 3 {
        return original;
    }
    // NSError may render the signed IOReturn as either signed-i32 or unsigned-u32.
    let code = u32::try_from(native_code)
        .ok()
        .or_else(|| i32::try_from(native_code).ok().map(|value| value as u32));
    // Exact public constants from Apple IOKit/IOReturn.h (iokit_common_err namespace).
    match code {
        Some(0xe000_02d8) => Bucket::IoNotReady, // kIOReturnNotReady
        Some(0xe000_02d9) => Bucket::IoNotAttached, // kIOReturnNotAttached
        Some(0xe000_02f0) => Bucket::IoNotFound, // kIOReturnNotFound
        Some(0xe000_02d7) => Bucket::IoOffline,  // kIOReturnOffline
        Some(0xe000_02c2) => Bucket::IoBadArgument, // kIOReturnBadArgument
        Some(0xe000_02be) => Bucket::IoNoResources, // kIOReturnNoResources
        Some(0xe000_02bf) => Bucket::IoIpcError, // kIOReturnIPCError
        Some(0xe000_02c9) => Bucket::IoInternalError, // kIOReturnInternalError
        Some(0xe000_02ca) => Bucket::IoError,    // kIOReturnIOError
        Some(0xe000_02bc) => Bucket::IoGeneralError, // kIOReturnError
        _ => original,
    }
}

/// Exact closed current-call provenance; it never changes native results or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceEvidence {
    status: u32,
    domain: u8,
    code: u8,
    reason: u8,
    under_domain: u8,
    under_code: u8,
}

/// Requires the emitter's canonical numeric grammar and closed namespace-specific tuples.
fn parse_evidence(line: &str) -> Option<InterfaceEvidence> {
    let mut body = line.strip_prefix("{\"diagnostic\":\"interface-init-evidence\",\"status\":")?;
    let mut values = [0u32; 6];
    for (index, delimiter) in [
        ",\"domain\":",
        ",\"code\":",
        ",\"reason\":",
        ",\"underDomain\":",
        ",\"underCode\":",
    ]
    .iter()
    .enumerate()
    {
        let (value, rest) = body.split_once(delimiter)?;
        values[index] = crate::scsi_worker_startup::canonical_status(value)?;
        body = rest;
    }
    values[5] = crate::scsi_worker_startup::canonical_status(body.strip_suffix('}')?)?;
    let [status, domain, code, reason, under_domain, under_code] = values;
    if status > 10
        || reason > 4
        || !valid_code(domain, code)
        || !valid_code(under_domain, under_code)
    {
        return None;
    }
    if (domain == 0 && (reason != 0 || under_domain != 0))
        || (domain == 5 && (reason != 4 || under_domain != 0))
    {
        return None;
    }
    Some(InterfaceEvidence {
        status,
        domain: domain as u8,
        code: code as u8,
        reason: reason as u8,
        under_domain: under_domain as u8,
        under_code: under_code as u8,
    })
}

/// Rejects impossible domain/code pairs rather than interpreting another error namespace.
fn valid_code(domain: u32, code: u32) -> bool {
    match domain {
        0 => code == 0,
        1 => (1..=20).contains(&code),
        2 => code == 1 || (21..=23).contains(&code),
        3..=6 => code == 1,
        _ => false,
    }
}

/// Correlates exactly one fresh record and its legacy return status, with fail-closed diagnostics.
#[derive(Default)]
pub(super) struct InterfaceEvidenceState {
    fresh: Option<InterfaceEvidence>,
    legacy_status: Option<u32>,
    invalid: bool,
}

impl InterfaceEvidenceState {
    /// Recognizes only the reserved emitter prefix; malformed records cannot reveal stale evidence.
    pub(super) fn fresh_line(&mut self, line: &str) -> bool {
        if !line.starts_with("{\"diagnostic\":\"interface-init-evidence\"") {
            return false;
        }
        if self.fresh.is_some() || self.legacy_status.is_some() {
            self.invalid = true;
        }
        match parse_evidence(line) {
            Some(record) => self.fresh = Some(record),
            None => self.invalid = true,
        }
        true
    }

    /// Rejects malformed legacy interface output only when it could contradict fresh evidence.
    pub(super) fn malformed_legacy(&mut self) {
        if self.fresh.is_some() {
            self.invalid = true;
        }
    }

    /// Checks the original status only; a stale legacy code is allowed and never overrides fresh data.
    pub(super) fn legacy(&mut self, status: u32) {
        let duplicate = self.legacy_status.replace(status).is_some();
        if self
            .fresh
            .is_some_and(|record| duplicate || record.status != status)
        {
            self.invalid = true;
        }
    }

    /// Invalidates a reserved record that was dropped by the existing bounded line parser.
    pub(super) fn malformed(&mut self) {
        self.invalid = true;
    }

    /// Rejects incomplete fresh transcripts when the existing parser budget is exhausted.
    pub(super) fn bounded_stop(&mut self) {
        if self.fresh.is_some() {
            self.invalid = true;
        }
    }

    /// Clears all transient records at fresh progress and successful READY.
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    /// Returns only a compiled token; retains the complete closed tuple privately for correlation.
    pub(super) fn code(&self) -> Option<&'static str> {
        if self.invalid {
            return Some("candidate-worker-usb-interface-fresh-evidence-invalid");
        }
        self.fresh.map(InterfaceEvidence::public_code)
    }
}

impl InterfaceEvidence {
    /// Namespace and reason classes are diagnostic observations, never proof of a transport cause.
    fn public_code(self) -> &'static str {
        macro_rules! domain_code {
            ($prefix:expr, $domain:expr, $code:expr) => {
                match ($domain, $code) {
                    (0, 0) => concat!($prefix, "missing"),
                    (1, 2) => concat!($prefix, "host-not-ready"),
                    (1, 3) => concat!($prefix, "host-not-attached"),
                    (1, 4) => concat!($prefix, "host-not-found"),
                    (1, 5) => concat!($prefix, "host-offline"),
                    (1, 6) => concat!($prefix, "host-bad-argument"),
                    (1, 7) => concat!($prefix, "host-no-resources"),
                    (1, 8) => concat!($prefix, "host-ipc-error"),
                    (1, 9) => concat!($prefix, "host-internal-error"),
                    (1, 10) => concat!($prefix, "host-io-error"),
                    (1, 11) => concat!($prefix, "host-error"),
                    (1, 12) => concat!($prefix, "host-not-privileged"),
                    (1, 13) => concat!($prefix, "host-busy"),
                    (1, 14) => concat!($prefix, "host-exclusive-access"),
                    (1, 15) => concat!($prefix, "host-timeout"),
                    (1, 16) => concat!($prefix, "host-no-device"),
                    (1, 17) => concat!($prefix, "host-not-open"),
                    (1, 18) => concat!($prefix, "host-unsupported"),
                    (1, 19) => concat!($prefix, "host-not-permitted"),
                    (1, 20) => concat!($prefix, "host-no-memory"),
                    (1, _) => concat!($prefix, "host-unknown"),
                    (2, 21) => concat!($prefix, "posix-permission"),
                    (2, 22) => concat!($prefix, "posix-not-found"),
                    (2, 23) => concat!($prefix, "posix-bad-fd"),
                    (2, _) => concat!($prefix, "posix-unknown"),
                    (3, _) => concat!($prefix, "cocoa-unknown"),
                    (4, _) => concat!($prefix, "other-unknown"),
                    (5, _) => concat!($prefix, "malformed"),
                    (6, _) => concat!($prefix, "mach-unknown"),
                    _ => "candidate-worker-usb-interface-fresh-evidence-invalid",
                }
            };
        }
        macro_rules! reason_code {
            ($prefix:literal) => {
                if self.under_domain == 0 {
                    domain_code!(concat!($prefix, "current-"), self.domain, self.code)
                } else {
                    domain_code!(
                        concat!($prefix, "under-"),
                        self.under_domain,
                        self.under_code
                    )
                }
            };
        }
        // Missing/malformed current errors have no meaningful reason or underlying object.
        if self.domain == 0 {
            return "candidate-worker-usb-interface-fresh-error-missing";
        }
        if self.domain == 5 {
            return "candidate-worker-usb-interface-fresh-error-malformed";
        }
        // Underlying evidence gets precedence only in the public token. The top-level domain/code
        // remains in the private tuple; no arbitrary strings, numeric codes or recursive objects escape.
        match self.reason {
            0 => reason_code!("candidate-worker-usb-interface-fresh-reason-missing-"),
            1 => reason_code!("candidate-worker-usb-interface-fresh-super-init-"),
            2 => reason_code!("candidate-worker-usb-interface-fresh-service-open-"),
            3 => reason_code!("candidate-worker-usb-interface-fresh-reason-unknown-"),
            _ => reason_code!("candidate-worker-usb-interface-fresh-reason-malformed-"),
        }
    }
}

/// Regression: a nil current NSError must not inherit an earlier shared-slot cause.
#[cfg(test)]
#[test]
fn fresh_missing_error_precedes_legacy_shared_error() {
    use crate::scsi_worker_startup::{StartupDiagnostics, reset, take_last_worker_startup_failure};
    reset();
    let mut observer = StartupDiagnostics::new(None);
    observer.consume(b"{\"diagnostic\":\"interface-init-evidence\",\"status\":3,\"domain\":0,\"code\":0,\"reason\":0,\"underDomain\":0,\"underCode\":0}\n");
    observer.consume(b"{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":3,\"nativeCodeKind\":\"nserror\",\"nativeCode\":3758097089}\n");
    observer.failure("init-read", crate::NativeError::TransportUnavailable);
    assert_eq!(
        take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-usb-interface-fresh-error-missing"
    );
}

#[cfg(test)]
mod fresh_tests {
    use super::*;
    use crate::scsi_worker_startup::{StartupDiagnostics, reset, take_last_worker_startup_failure};

    /// Serializes only the exact bounded formatter for hardware-free transcript fixtures.
    fn record(
        status: u32,
        domain: u8,
        code: u8,
        reason: u8,
        under_domain: u8,
        under_code: u8,
    ) -> String {
        format!(
            "{{\"diagnostic\":\"interface-init-evidence\",\"status\":{status},\"domain\":{domain},\"code\":{code},\"reason\":{reason},\"underDomain\":{under_domain},\"underCode\":{under_code}}}"
        )
    }

    /// Finishes an unchanged EOF failure and returns only its compiled diagnostic token.
    fn transcript(lines: &[&str]) -> &'static str {
        reset();
        let mut observer = StartupDiagnostics::new(None);
        for line in lines {
            observer.consume(line.as_bytes());
            observer.consume(b"\n");
        }
        observer.failure("init-read", crate::NativeError::TransportUnavailable);
        take_last_worker_startup_failure().unwrap().code()
    }

    /// Known, missing, unknown and malformed classes retain namespace-specific provenance.
    #[test]
    fn current_error_classes_are_closed_and_path_free() {
        for (tuple, expected) in [
            ((1, 9, 1, 2, 21), "super-init-under-posix-permission"),
            ((1, 9, 0, 1, 2), "reason-missing-under-host-not-ready"),
            ((1, 9, 2, 6, 1), "service-open-under-mach-unknown"),
            (
                (1, 9, 4, 0, 0),
                "reason-malformed-current-host-internal-error",
            ),
            ((1, 9, 3, 5, 1), "reason-unknown-under-malformed"),
            ((2, 1, 0, 0, 0), "reason-missing-current-posix-unknown"),
            ((3, 1, 0, 0, 0), "reason-missing-current-cocoa-unknown"),
            ((4, 1, 3, 0, 0), "reason-unknown-current-other-unknown"),
            ((6, 1, 0, 0, 0), "reason-missing-current-mach-unknown"),
        ] {
            let (domain, code, reason, under_domain, under_code) = tuple;
            let line = record(10, domain, code, reason, under_domain, under_code);
            let code = transcript(&[&line]);
            assert_eq!(
                code,
                format!("candidate-worker-usb-interface-fresh-{expected}")
            );
            assert!(code.len() <= 128);
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            );
        }
    }

    /// Unknown properties, namespace collisions, noncanonical values and contradictions fail closed.
    #[test]
    fn malformed_or_duplicate_fresh_evidence_cannot_fall_back_to_legacy_error() {
        let valid = record(10, 1, 9, 1, 2, 21);
        let legacy = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":10,\"nativeCodeKind\":\"nserror\",\"nativeCode\":3758097097}";
        assert!(transcript(&[&valid, legacy]).contains("super-init-under-posix-permission"));
        for lines in [
            vec![valid.as_str(), valid.as_str()],
            vec![valid.as_str(), legacy, legacy],
            vec![legacy, valid.as_str()],
        ] {
            assert_eq!(
                transcript(&lines),
                "candidate-worker-usb-interface-fresh-evidence-invalid"
            );
        }
        assert_eq!(
            transcript(&[&record(3, 0, 0, 0, 0, 0), legacy]),
            "candidate-worker-usb-interface-fresh-evidence-invalid"
        );
        for bad in [
            valid.replace("\"domain\":1", "\"domain\":2"),
            valid.replace("\"status\":10", "\"status\":010"),
            valid.replace("\"status\":10", "\"status\":11"),
            valid.replace("\"reason\":1", "\"reason\":5"),
            valid.replace("\"underDomain\":2", "\"underDomain\":6"),
            valid.replace("}", ",\"path\":\"/private/secret\"}"),
            format!("{}{}", &valid[..valid.len() - 1], "x".repeat(400)),
        ] {
            assert_eq!(
                transcript(&[&bad, legacy]),
                "candidate-worker-usb-interface-fresh-evidence-invalid"
            );
        }
        for (domain, code) in [(0, 1), (1, 21), (2, 9), (3, 9), (6, 9), (7, 1)] {
            assert!(parse_evidence(&record(10, domain, code, 0, 0, 0)).is_none());
        }
        assert!(parse_evidence(&record(10, 0, 0, 1, 0, 0)).is_none());
        assert!(parse_evidence(&record(10, 5, 1, 4, 1, 9)).is_none());
    }

    /// Invalid UTF-8, malformed legacy correlation and exhausted parsing remain diagnostic-only.
    #[test]
    fn truncated_and_non_utf8_transcripts_do_not_publish_stale_causes() {
        let valid = record(10, 1, 9, 1, 2, 21);
        let malformed_legacy = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":invalid}";
        assert_eq!(
            transcript(&[&valid, malformed_legacy]),
            "candidate-worker-usb-interface-fresh-evidence-invalid"
        );
        for data in [
            [
                b"{\"diagnostic\":\"interface-init-evidence\"".as_slice(),
                &[255],
                b"\n",
            ]
            .concat(),
            [valid.as_bytes(), b"\n", &vec![b'x'; 9_000]].concat(),
        ] {
            reset();
            let mut observer = StartupDiagnostics::new(None);
            observer.consume(&data);
            observer.failure("init-read", crate::NativeError::TransportUnavailable);
            assert_eq!(
                take_last_worker_startup_failure().unwrap().code(),
                "candidate-worker-usb-interface-fresh-evidence-invalid"
            );
        }
        // The legacy nil-constructor + shared NSError code zero edge remains a valid status,
        // even though diagnostics must never use that status as protocol or acquisition authority.
        assert!(parse_evidence(&record(0, 1, 1, 0, 0, 0)).is_some());
        let old = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":10,\"nativeCodeKind\":\"nserror\",\"nativeCode\":3758097097}";
        assert_eq!(
            transcript(&[old, old]),
            "candidate-worker-usb-open-interface-io-internal-error"
        );
    }

    /// READY and subsequent successful progress clear every fresh or invalid transient record.
    #[test]
    fn ready_and_fresh_progress_discard_current_call_evidence() {
        let valid = record(10, 1, 9, 1, 2, 21);
        let progress = "{\"diagnostic\":\"worker-startup\",\"stage\":\"ready-write\",\"status\":0}";
        assert_eq!(
            transcript(&[&valid, progress]),
            "candidate-worker-ready-write-transport-unavailable"
        );
        reset();
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(valid.as_bytes());
        observer.consume(b"\n");
        observer.success();
        observer.failure("init-read", crate::NativeError::TransportUnavailable);
        assert!(take_last_worker_startup_failure().is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeError;
    use crate::scsi_worker_startup::{
        NativeDiagnostic, StartupDiagnostics, bucket, parse_native, reset,
        take_last_worker_startup_failure,
    };
    const NATIVE_STAGES: &[&str] = &[
        "legacy-create-plugin",
        "usb-open-interface",
        "usb-capture-device",
        "usb-open-bulk-in",
    ];
    /// Regression: standard interface readiness evidence retains its fixed diagnostic class.
    #[test]
    fn interface_open_standard_ioreturn_is_a_fixed_diagnostic_class() {
        let line = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":10,\"nativeCodeKind\":\"nserror\",\"nativeCode\":3758097112}";
        assert_eq!(
            parse_native(line).unwrap().failure.code(),
            "candidate-worker-usb-open-interface-io-not-ready"
        );
    }

    /// Builds only the existing closed formatter; test inputs never reach native acquisition.
    fn interface_record(stage: &str, status: u32, kind: &str, code: i64) -> NativeDiagnostic {
        parse_native(&format!("{{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"{stage}\",\"nativeStatus\":{status},\"nativeCodeKind\":\"{kind}\",\"nativeCode\":{code}}}")).unwrap()
    }

    /// Signed and unsigned representations of exact SDK constants produce the same fixed code.
    #[test]
    fn interface_open_sdk_whitelist_normalizes_only_i32_or_u32() {
        for (value, suffix) in [
            (0xe000_02d8u32, "io-not-ready"),
            (0xe000_02d9, "io-not-attached"),
            (0xe000_02f0, "io-not-found"),
            (0xe000_02d7, "io-offline"),
            (0xe000_02c2, "io-bad-argument"),
            (0xe000_02be, "io-no-resources"),
            (0xe000_02bf, "io-ipc-error"),
            (0xe000_02c9, "io-internal-error"),
            (0xe000_02ca, "io-error"),
            (0xe000_02bc, "io-general-error"),
        ] {
            let positive = interface_record("usb-open-interface", 10, "nserror", i64::from(value));
            let negative =
                interface_record("usb-open-interface", 10, "nserror", i64::from(value as i32));
            assert_eq!(positive.failure, negative.failure);
            assert_eq!(
                positive.failure.code(),
                format!("candidate-worker-usb-open-interface-{suffix}")
            );
            assert!(positive.failure.code().len() <= 128);
            assert!(
                positive
                    .failure
                    .code()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            );
            // Private evidence remains exact; public codes contain no numeric/native text.
            assert_eq!(positive._native_code, i64::from(value));
            assert_eq!(negative._native_code, i64::from(value as i32));
        }
        for code in [
            i64::MIN,
            i64::MAX,
            -2_147_483_649,
            4_294_967_296,
            0,
            -1,
            0xe000_4001,
            0xe000_02bd,
        ] {
            assert_eq!(
                interface_record("usb-open-interface", 10, "nserror", code)
                    .failure
                    .code(),
                "candidate-worker-usb-open-interface-other"
            );
        }
    }

    /// Other stages, known status buckets and non-NSError namespaces are unchanged.
    #[test]
    fn interface_classification_requires_exact_stage_status_and_code_namespace() {
        for &stage in NATIVE_STAGES {
            let record = interface_record(stage, 10, "nserror", 0xe000_02d8);
            if stage != "usb-open-interface" {
                assert_eq!(record.failure.bucket, Bucket::Other);
            }
        }
        for status in 1..=9 {
            let record = interface_record("usb-open-interface", status, "nserror", 0xe000_02d8);
            assert_eq!(
                record.failure.bucket,
                bucket(crate::boundary::status_error(status))
            );
        }
        for kind in ["ioreturn", "hresult"] {
            assert_eq!(
                interface_record("usb-open-interface", 10, kind, 0xe000_02d8)
                    .failure
                    .bucket,
                Bucket::Other
            );
        }
        assert_eq!(
            interface_record("usb-open-interface", 10, "none", 0)
                .failure
                .code(),
            "candidate-worker-usb-open-interface-error-missing"
        );
        assert_eq!(
            interface_record("usb-open-interface", 10, "nserror", 0)
                .failure
                .bucket,
            Bucket::Other
        );
        assert_eq!(
            interface_record("usb-open-interface", 3, "none", 0)
                .failure
                .bucket,
            Bucket::Denied
        );
        assert_eq!(
            interface_record("usb-capture-device", 10, "none", 0)
                .failure
                .bucket,
            Bucket::Other
        );
        assert!(parse_native("{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":10,\"nativeCodeKind\":\"none\",\"nativeCode\":3758097112}").is_none());
    }

    /// An existing precleanup record yields only the compiled class and successful READY clears it.
    #[test]
    fn interface_classification_is_evidence_only_and_success_still_clears() {
        reset();
        let line = b"{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":10,\"nativeCodeKind\":\"nserror\",\"nativeCode\":3758097097}\n";
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(line);
        observer.failure("init-read", NativeError::TransportUnavailable);
        assert_eq!(
            take_last_worker_startup_failure().unwrap().code(),
            "candidate-worker-usb-open-interface-io-internal-error"
        );
        assert!(take_last_worker_startup_failure().is_none());
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(line);
        observer.success();
        observer.failure("init-read", NativeError::TransportUnavailable);
        assert!(take_last_worker_startup_failure().is_none());
    }
}
