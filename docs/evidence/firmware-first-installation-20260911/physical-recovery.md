# Physical migration failure and recovery checkpoint, 2026-09-11

## Observed state

The selected empty-bay vendor 2.83 dock underwent the documented first-install
route. Operation `op:2987669f-bd31-4b9a-bb1e-7ba1739c4fc7` published:

- `12:20:21.593Z`: capture; compatibility setup and staging followed.
- `12:20:24.284Z`: first operator power-cycle wait.
- `12:22:09.498Z`: ROM bootstrap programming.
- `12:22:12.778Z`: second operator power-cycle wait.
- `12:22:41.481Z`: preserved-record verification stage.
- `12:22:41.509Z`: nonzero service exit and failed operation.

A read-only IORegistry observation then showed the original USB serial and
`1A5A:0005`, revision `0107`, at the original location. This identifies a running
receiver, not installation of the unmodified final release.

The later ordinary retry `op:d2937ffe-c786-494f-942a-b4121e38675e` published
validation at `12:24:00.085Z`, then the host rejected service data at `.097Z`.
Ten native commands had completed and an eleventh had entered without returning.
This is consistent with validation followed by the first firmware chunk, but the
redacted breadcrumbs do not prove the command identity or completed erase.

The user subsequently moved the USB cable. Fresh IORegistry reported
`0451:926B` (TI ROM loader) at a different location. J7 was not bridged according
to the user's account. No further hardware commands were issued during this
diagnosis. The unlit LED does not establish loss of electrical power; the ROM
loader's observed enumeration establishes that its USB interface is available.

## Confirmed source defects

1. The host sent unsupported vendor READ BUFFER to the OpenRDX receiver.
   The fixed `E7` reader now covers both complete preserved records over BOT.
2. Native lifecycle validation rejected an early, completion-unknown migration
   terminal, turning that failure into service exit code 3. Exact-stage failure
   handling now retains explicit incomplete cleanup evidence.
3. JavaScript's shadow publication validator rejected the ordinary direct
   validation-to-writing transition after the migration stages were added.
   It now uses the same transition predicate as the coordinator.

The firmware's ordinary first-chunk handler erases the first 64 KiB and withholds
the boot vector until successful mode-5 activation. An interrupted ordinary
transfer can therefore explain the later ROM state. This remains an inference
from source and timing, not a raw flash observation.

## Private recovery evidence

The user ran the prepared root-only Python diagnostic from Terminal. It returned
one original bundle with `integrity: true`. Its verified journal ends with
`awaiting-bootstrap-power-cycle`, then `recovery-required`. It contains no
`bootstrap-readback-verified`, `final-update-started`, or final verification event.

Private capture data, reconstructed records, receipts and personalized bytes
remain in `/private/var/db/OpenRDXManager/recovery`. No unit-private fields or
hashes are included in this document. The bundle is a saved semantic
reconstruction of exposed vendor records, not a raw original SPI backup.

Recovery cold-validates that original bundle, preserves it unchanged, and uses
a separate attempt with explicit provenance. The built-in recovery workflow now
accepts a freshly selected ROM dock on any USB port. The operator associates that
physical dock with its saved profile; neither a generic ROM serial nor VID/PID
establishes unit identity. Native code binds the selection to the observed USB
registry epoch and checks for conflicting unit identity before setup. It programs
only the saved bootstrap, requires an operator power-cycle acknowledgment, reads
and compares all records, then transfers the exact public 1.07 image and verifies
again. The original captured port remains immutable evidence. An integrity check
alone does not initiate a recovery write.

## Verification checkpoint

- 122 focused JavaScript lifecycle/service regressions passed.
- Actual-byte emulation verifies all three E7 reads in both pinned images;
  20 bootstrap/emulator tests passed with synthetic flash only.
- Native E7 wire/BOT tests and strict C syntax checks passed; the broader native
  crate retains the previously observed unrelated mounted-filesystem assertion.
- The corrected development helper and the first dedicated recovery-controller
  version built successfully. Later review fixes still require rebuilding.
- Newly built service tests subsequently stalled in macOS before application
  entry (`_dyld_start`); their execution must not be reported as passing.
- Final native checks, recovery-controller tests, Electron smoke and physical
  recovery remain required. No completed installation is claimed.

The final read-only helper startup probe also exceeded its eight-second bound
and was terminated without entering a hardware mode. No helper, compiler or
firmware transfer remained running when the operator was asked to restart macOS.
The last IORegistry check still showed the TI ROM loader on the moved USB port.

Source changes saved for verification after restart include fresh terminal-input
arming, failure journaling before capture teardown, and bounded parent IPC for
the disposable SCSI worker. Initialization, private identity reads, command I/O,
shutdown and child reaping now have explicit deadlines; timeout invalidates the
lease rather than permitting another frame on a partial stream. Those latest
changes have format/diff checks only; their focused tests have not executed.

## Checkpoint after the Mac restart and built-in any-port implementation

The user returned the dock to the original port. Read-only IORegistry again
reported the TI ROM loader there. No recovery writes were issued during the
software checks below, and physical recovery remains unverified.

- The complete native service suite passed: 565 tests, one ignored.
- After the final selected-port changes, all 25 recovery controller/session tests
  passed. The macOS native suite passed 40 tests with the separately known
  mounted-filesystem assertion excluded.
- Native formatting, all-target compilation and Clippy passed with all features
  and with no default features.
- The main-process recovery admission, lifecycle, runtime and shutdown suites
  passed 53 tests. Renderer/preload/recovery suites passed 98 tests.
- A full JavaScript run exposed a bare Zod import that Chromium could not resolve
  from the unbundled renderer, plus missing MCP coverage for the four new recovery
  routes. The import now follows the existing browser-resolvable shared-schema
  pattern. Closed MCP recovery routes require explicit selection and physical
  acknowledgment; their focused tests passed.
- The final full JavaScript run passed 805 of 807 tests. The remaining failures
  were screenshot-set repeatability (the previously observed visual evidence
  instability) and the process-tree timeout assertion under concurrent suite
  load. The complete platform-verification file passed all 12 tests when rerun
  independently. The renderer startup regression is resolved; both real Electron
  console-error checks and the wrong-raster rejection passed.
- The current runtime rebuilt successfully and `npm run smoke` passed with the
  renderer mounted. Its unprivileged service was unavailable, as expected; this
  is application startup evidence, not privileged hardware verification.
- `npm run format:check` and `git diff --check` passed. Test-generated changes to
  previously clean visual evidence were restored; the two pre-existing Utilities
  captures were retained.

At that checkpoint, the next hardware step was the built-in Manager recovery screen, using its
privileged development service. It must still demonstrate the operator
power-cycle gate, exact record readback and final release verification before
this incident can be described as recovered.

## Completed physical recovery, 16:26–16:27 UTC

The user launched the rebuilt Manager with its authorized development helper.
The real Electron window displayed the TI ROM recovery panel and offered the
validated original profile. The operator selected that profile and the currently
connected ROM dock at USB location `0x00200000`, confirmed the physical association,
and clicked **Start recovery**. UI automation could observe the window but could
not activate its controls, so the operator performed the selections and clicks.

Manager reached **Waiting for your USB power cycle** after its ROM programming
and reset stages. The operator disconnected/reconnected USB at the selected port,
left J7 open and the bay empty, and clicked **Continue after reconnecting**.
The real window subsequently displayed:

> Recovery completed. The final OpenRDX release and the restored dock records were verified.

The normal RDX inventory returned with the original unit identity and no
cartridge. At `16:27:07 UTC`, an independent read-only IORegistry query confirmed
product `RDX`, USB `1A5A:0005`, descriptor revision `0107`, the original USB serial,
and location `0x00200000`. A contemporaneous CUA screenshot and accessibility
observation showed the completed recovery and hardware-connected state.

The success state is gated by the native controller's accepted final mode-5
activation, a new USB enumeration epoch, fresh product/revision/empty-bay checks,
and comparison of all 320 saved manufacturing/operational record bytes after
the final transfer. The transferred release is the pinned public 1.07 image.
This is not an independent full executable-flash dump. The root-owned journal
was not separately reopened from the unprivileged agent session after completion.

This physically verifies recovery of the failed migration through Manager on
macOS without J7. The attempt used the original port; different-port selection
has software/native-boundary test coverage but was not separately exercised in
this successful hardware attempt. A new uninterrupted vendor-2.83 first
installation and recovery without valid saved unit data are not established
by this result. No further firmware writes were performed after success.
