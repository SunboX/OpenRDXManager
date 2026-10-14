// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded test-only phase formatting: static boolean tuples only, with no kernel handles or authority.
use std::cell::RefCell;
use std::io::Write;

/// Fixed record namespaces keep observational lineage separate from matrix admission facts.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Prefix {
    Matrix,
    Lineage,
}
/// Closed formatter errors, never arbitrary IO strings.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Error {
    Context,
    Bound,
    Io,
}
/// One phase stores only static keys and booleans, not SDK buffers/identities/paths.
struct Record {
    row: &'static str,
    phase: &'static str,
    values: Vec<(Prefix, &'static str, bool)>,
    error: Option<Error>,
}
thread_local! { static ACTIVE:RefCell<Option<Record>> = const {RefCell::new(None)}; }
const MAX_VALUES: usize = 128;
const MAX_BYTES: usize = 8192;

/// Only the compiled matrix roles and phases are accepted; no outside/nested context is adopted.
fn context(row: &str, phase: &str) -> bool {
    if row == "matrix" {
        return ["setup", "fixture", "cleanup", "source-check", "complete"].contains(&phase);
    }
    [
        "baseline",
        "process",
        "thread",
        "process-thread",
        "token",
        "process-token",
        "thread-token",
        "process-thread-token",
    ]
    .contains(&row)
        && [
            "derive",
            "reference-create",
            "reference-read",
            "reference-resume",
            "reference-wait",
            "reference-reap",
            "intervention",
            "create",
            "read",
            "resume",
            "wait",
            "reap",
            "positive-create",
            "positive-read",
            "positive-resume",
            "positive-wait",
            "positive-reap",
            "cleanup",
            "source-check",
            "complete",
        ]
        .contains(&phase)
}
/// The lineage namespace is read-only and belongs only to the four fixed token rows/read and source endpoints.
fn prefix_context(prefix: Prefix, row: &str, phase: &str) -> bool {
    prefix == Prefix::Matrix
        || (row == "matrix" && ["setup", "source-check"].contains(&phase))
        || ([
            "token",
            "process-token",
            "thread-token",
            "process-thread-token",
        ]
        .contains(&row)
            && phase == "read")
}
/// Retains every tuple or records a fatal formatting error; no invalid fact is silently dropped.
pub(super) fn record(
    prefix: Prefix,
    row: &'static str,
    phase: &'static str,
    values: &[(&'static str, bool)],
) {
    ACTIVE.with(|active| {
        let mut state = active.borrow_mut();
        let Some(record) = state.as_mut() else {
            panic!("matrix-output-context-required");
        };
        if record.row != row || record.phase != phase || !prefix_context(prefix, row, phase) {
            record.error.get_or_insert(Error::Context);
            return;
        }
        for (key, value) in values {
            if key.is_empty()
                || key.len() > 64
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                || record
                    .values
                    .iter()
                    .any(|(p, k, _)| *p == prefix && k == key)
            {
                record.error.get_or_insert(Error::Context);
                return;
            }
            let bytes: usize = record.values.iter().map(|(_, key, _)| key.len() + 7).sum();
            if record.values.len() >= MAX_VALUES || bytes + key.len() + 7 > MAX_BYTES {
                record.error.get_or_insert(Error::Bound);
                return;
            }
            record.values.push((prefix, key, *value));
        }
    });
}
/// Owns only its thread-local phase buffer; invalid nested activation never replaces another phase.
pub(super) struct Phase {
    row: &'static str,
    phase: &'static str,
    active: bool,
}
impl Phase {
    /// Establishes a bounded phase before an operation emits facts.
    pub(super) fn begin(row: &'static str, phase: &'static str) -> Result<Self, Error> {
        if !context(row, phase) {
            return Err(Error::Context);
        }
        ACTIVE.with(|active| {
            let mut state = active.borrow_mut();
            if let Some(record) = state.as_mut() {
                record.error.get_or_insert(Error::Context);
                return Err(Error::Context);
            }
            *state = Some(Record {
                row,
                phase,
                values: Vec::new(),
                error: None,
            });
            Ok(Self {
                row,
                phase,
                active: true,
            })
        })
    }
    /// Writes at most one record per fixed prefix, preserving all values before the phase terminal marker.
    pub(super) fn flush(&mut self, writer: &mut impl Write) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Context);
        }
        let record = ACTIVE
            .with(|active| active.borrow_mut().take())
            .ok_or(Error::Context)?;
        self.active = false;
        if record.row != self.row || record.phase != self.phase {
            return Err(Error::Context);
        }
        for prefix in [Prefix::Matrix, Prefix::Lineage] {
            let values: Vec<_> = record
                .values
                .iter()
                .filter(|(p, _, _)| *p == prefix)
                .collect();
            if values.is_empty() {
                continue;
            }
            let name = if prefix == Prefix::Matrix {
                "openrdx-token-object-dacl-matrix"
            } else {
                "openrdx-token-object-lineage"
            };
            let pairs = values
                .iter()
                .map(|(_, key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(" ");
            writeln!(
                writer,
                "{name} row={} phase={} {pairs}",
                record.row, record.phase
            )
            .map_err(|_| Error::Io)?;
        }
        record.error.map_or(Ok(()), Err)
    }
}
impl Drop for Phase {
    /// Best effort on panic preserves caller unwinding and leaves no stale TLS phase; no terminal success is forged.
    fn drop(&mut self) {
        if self.active {
            let _ = self.flush(&mut std::io::stdout().lock());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Multiple normal calls preserve all tuples while using one record for each namespace.
    #[test]
    fn grouped_fields_are_preserved() {
        let mut phase = Phase::begin("token", "read").unwrap_or_else(|_| panic!("begin"));
        record(Prefix::Matrix, "token", "read", &[("query-ok", true)]);
        record(Prefix::Matrix, "token", "read", &[("exact", false)]);
        record(Prefix::Lineage, "token", "read", &[("fresh-proof", true)]);
        let mut bytes = Vec::new();
        assert!(phase.flush(&mut bytes).is_ok());
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text == "openrdx-token-object-dacl-matrix row=token phase=read query-ok=true exact=false\nopenrdx-token-object-lineage row=token phase=read fresh-proof=true\n"
        );
    }
    /// Unknown/nested/mismatched/duplicate context stays fatal rather than discarding a fact unnoticed.
    #[test]
    fn invalid_context_is_fatal() {
        assert!(Phase::begin("unknown", "read").is_err());
        let mut phase = Phase::begin("token", "read").unwrap_or_else(|_| panic!("begin"));
        assert!(Phase::begin("process", "read").is_err());
        record(Prefix::Matrix, "token", "read", &[("query-ok", true)]);
        record(Prefix::Matrix, "token", "read", &[("query-ok", true)]);
        let mut bytes = Vec::new();
        assert!(phase.flush(&mut bytes).is_err());
        assert!(!bytes.is_empty());
        let mut wrong = Phase::begin("token", "read").unwrap_or_else(|_| panic!("begin"));
        record(Prefix::Lineage, "thread", "read", &[("fresh-proof", true)]);
        assert!(wrong.flush(&mut Vec::new()).is_err());
    }
    /// A repeated key alone is fatal even when no other context error occurred.
    #[test]
    fn duplicate_alone_is_fatal() {
        let mut phase = Phase::begin("token", "read").unwrap_or_else(|_| panic!("begin"));
        record(Prefix::Matrix, "token", "read", &[("query-ok", true)]);
        record(Prefix::Matrix, "token", "read", &[("query-ok", false)]);
        assert!(matches!(phase.flush(&mut Vec::new()), Err(Error::Context)));
    }
    /// A missing active phase panics with a fixed tag and cannot manufacture output or acceptance.
    #[test]
    fn missing_phase_is_fatal() {
        assert!(
            std::panic::catch_unwind(|| {
                record(Prefix::Matrix, "token", "read", &[("query-ok", true)]);
            })
            .is_err()
        );
    }
    /// Oversized phases and writer failure are closed errors; metadata never grows without a bound.
    #[test]
    fn limits_and_writer_errors_are_fatal() {
        let mut phase = Phase::begin("token", "read").unwrap_or_else(|_| panic!("begin"));
        for index in 0..129 {
            let key: &'static str = Box::leak(
                format!(
                    "key-{}{}",
                    (b'a' + (index / 26) as u8) as char,
                    (b'a' + (index % 26) as u8) as char
                )
                .into_boxed_str(),
            );
            record(Prefix::Matrix, "token", "read", &[(key, true)]);
        }
        assert!(phase.flush(&mut Vec::new()).is_err());
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut phase = Phase::begin("token", "read").unwrap_or_else(|_| panic!("begin"));
        record(Prefix::Matrix, "token", "read", &[("query-ok", true)]);
        assert!(matches!(phase.flush(&mut Broken), Err(Error::Io)));
    }
    /// Best-effort flushing during unwinding clears the phase before any later checkpoint.
    #[test]
    fn unwind_clears_only_owned_phase() {
        let result = std::panic::catch_unwind(|| {
            let _phase = Phase::begin("token", "read").unwrap_or_else(|_| panic!("begin"));
            record(Prefix::Matrix, "token", "read", &[("query-ok", true)]);
            panic!("fixed-test-panic");
        });
        assert!(result.is_err());
        let mut next = Phase::begin("token", "read").unwrap_or_else(|_| panic!("stale"));
        assert!(next.flush(&mut Vec::new()).is_ok());
    }
}
