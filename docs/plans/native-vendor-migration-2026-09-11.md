<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Native vendor migration implementation plan — 2026-09-11

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Selecting the published OpenRDX 1.07 release in Manager can complete installation from the researched USB3/SATA3 vendor 0283 dock, preserve its exposed identity/state, and report verified completion.

**Architecture:** Retain the existing single hardware owner and firmware-operation lock. Add native Rust record preparation and private durable recovery storage, plus an Apple-framework ROM transport; do not add a renderer hardware API or a Python runtime dependency. The normal OpenRDX update path remains responsible for the final unmodified release transfer, finalizer and readback.

**Spec:** `docs/protocols/vendor-migration.md`, `analysis/prototype/README.md`, `analysis/prototype/RECOVERY_BUNDLE.md`, and the explicit user requirement to migrate without opening the dock in the normal flow.

## Constraints

- Preserve the user-owned unrelated working-tree changes.
- Immutable vendor inputs and private real-device capture remain untouched.
- Admit only the exact reviewed bootstrap and published 1.07 container; retain independent normal vendor RSA checks.
- Use the actual observed USB serial and physical location, never a synthesized serial or VID/PID-only match.
- Save, sync and reopen the complete per-device recovery material before any firmware write.
- Preserve all exposed fields; record honestly that unexposed SPI bytes are not a raw backup.
- Unknown transfer outcomes stop; do not automatically replay a partial ROM stream or reset after a failed ROM program.
- Do not remove the existing receiver gate without a complete replacement workflow.
- No hardware transition until the source-to-ROM method, transport, recovery artifacts and final receiver path have been reviewed together. A transport test is not physical installation proof.

## Native record preparation

- [x] Add synthetic rejection and roundtrip tests matching the current Python reference decoder.
- [x] Implement `migration` Rust module with bounded USB identity and capture inputs, package construction and template personalization.
- [x] Independently compare restored observations, preserving the distinction between reported revision and image-content evidence.
- [x] Persist source capture, personalized bootstrap, final release and a separately retained receipt/journal in private fixed service-owned storage; reopen and verify before return.
- [ ] Run focused native tests and Clippy without opening hardware.

## Native ROM transport

- [x] Add an isolated `macos-native::rom` wrapper and C/Objective-C implementation using Apple frameworks.
- [x] Match the exact captured location and one 0451:926B USB parent, discover the HID and vendor bulk interface/endpoint 02.
- [x] Read only the documented 6092 feature identifier during transport preflight.
- [x] Expose separate bounded setup, full-image bulk and reset operations so the owner can journal each intent before calling it.
- [x] Test descriptor selection, lengths, short/error outcomes and release ownership without physical I/O.

## Integration and source transition

- [x] Add only the two fixed factory READ BUFFER commands to the trusted native protocol vocabulary.
- [x] Obtain fresh source factory/state responses and USB-parent identity through the same selected device operation.
- [x] Compare the manual and updater script: two fixed compatibility setup requests, complete mode-04 staging with exact final 07/74/08, no vendor mode-05, and prompted ROM entry with J7 open.
- [x] Replace receiver-required rejection only where a complete admitted migration plan is available.
- [ ] Preserve operation cancellation before writing; keep the application lock through transition, programming, record verification and final ordinary update.
- [ ] Test the complete operation using deterministic transport observations and all failure boundaries.
- [ ] Run native checks, relevant full tests, formatting and Electron smoke. Inspect the actual UI before claiming a working Manager flow.
- [ ] Perform selected-device qualification only after the complete route is reviewable. Completion requires final unmodified-release transfer evidence, fresh 0107 identity and matching restored fields.

## Operator continuation

- [ ] Bind both Continue-after-reconnecting actions to the exact operation/stage,
      accepting each once without releasing the global lock.
- [ ] Reject stale, duplicated or skipped acknowledgements; a ROM reset that
      automatically boots OpenRDX must not race the unplug instruction.
- [ ] Verify actual runtime PID5 while retaining factory-record PID6, the original
      serial and physical USB location.

## Built-in recovery after interruption

The subsequent explicit user requirement removes the original-port restriction
for a new recovery attempt. The original capture and artifacts remain immutable.
Manager enumerates ROM-mode docks independently of normal storage discovery and
lets the user associate one observed physical dock with the saved unit profile.
Generic ROM identity is never treated as per-unit identity. Session-issued
selection tokens bind the current registry epoch, expire, and are consumed once.
The selected route remains fixed during that attempt; stale or replacement
devices fail before dependent commands. Restored serial and every saved record
byte are checked before the unmodified final release is transferred.

- [x] Add read-only ROM candidate inventory and epoch-bound selected transport.
- [x] Expose only validated saved-unit summaries, retaining private artifacts.
- [x] Adapt the controller to a newly selected port without modifying the source.
- [x] Add service-owned recovery progress, one-use continuation, and ordinary
      operation exclusion under the existing native global owner.
- [x] Wire closed main/preload recovery methods and synchronous admission/shutdown
      exclusion; preserve uncertainty until a fresh native status reconciles it.
- [ ] Verify automatic recovery discovery, UI progress/reload behavior and clear
      per-cause messages in the real Electron window.
- [ ] Finish independent review and full relevant software checks.
- [ ] Recover the selected physical dock through Manager and verify final 1.07.

No completed physical installation is implied by these implementation items.
