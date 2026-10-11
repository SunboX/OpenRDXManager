<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Diagnostic feedback

The Tests workspace reports submission immediately for Self Test, LED Test, and
Write/Read Test. While admission is pending, its diagnostic actions cannot be
submitted again. A rejected request displays a red start-failure panel and the
bounded service reason. Admission alone never produces a passed result.

Native queued, running, progress, and terminal events remain authoritative.
Confirmed completion displays the existing green passed panel; native failures
retain their stage, primary/cleanup evidence, and support reference. The feedback
appears beside the Run control and persists through background discovery updates.
A new request hides the previous result until its own outcome is known.

## Cause and implementation

`src/renderer/intent-adapter.mjs` previously discarded the result of
`operations.start`, including rejection before a queued event existed. It now
provides an optional result callback validated against the existing start-response
schema. `src/renderer/diagnostic-submission.mjs` keeps this admission state separate
from native execution, correlates events, and ignores late acknowledgements or
responses after teardown.

`src/renderer/views/tests-view.mjs` also required the current snapshot revision to
match a diagnostic's original revision before showing progress or its result.
Auto Scan could therefore hide valid evidence. Presentation now matches the
selected device and diagnostic kind. Command admission and native event matching
still use the original exact revision checks; no hardware safety gate changed.

## Verification

`test/diagnostic-feedback.test.mjs` exercises the actual delegated button,
production intent adapter, service event binding, and renderer store. It covers
immediate submission, duplicate clicks, rejected/throwing/malformed responses,
all three diagnostic kinds, late acknowledgements, native progress, passed/failed
results, newer Auto Scan snapshots, and teardown. These are deterministic bridge
and renderer tests, not a claim that a physical drive passed its self-test.

On 2026-09-11 at 06:28:21–06:28:22 UTC, a live Self Test was run from the reloaded
Electron Tests view on the selected Tandberg dock with its cartridge inserted.
The local activity log records operation
`op:a17e9b85-9296-4f3d-ac2b-07f495a65d23` progressing through queued,
`diagnostic-running`, `diagnostic-cleanup`, and succeeded/complete. The actual
window displayed the green **Self Test passed** panel, **SCSI GOOD**, and exact
device revalidation. A subsequent UI read confirmed the result remained visible
with Auto Scan enabled. LED and Write/Read feedback were verified by deterministic
tests; those diagnostics were not run on the physical cartridge in this change.

The final focused renderer/diagnostic command passed 30 tests. Formatting and the
Electron smoke check passed. The full suite completed with 714 passes and three
reported failures (including a parent failure), in two Electron visual checks:
a keyboard-focus assertion and a visual-run timeout. The unprivileged smoke run
mounted the renderer with the hardware service unavailable; the live UI result
above is the separate connected-device evidence.
