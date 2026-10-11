<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Implementation roadmap — 2026-08-25

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Deliver the approved full OpenRDXManager design through four independently reviewable, test-first implementation phases.

**Architecture:** Build the sandboxed Electron product shell and typed boundary first, then the portable Rust protocol/service core, then native platform adapters, and finally the complete user-visible feature set. Each phase preserves a runnable no-device state and adds verification without depending on physical hardware being attached.

**Technology:** Electron 44, Node.js native ESM, HTML/CSS, Phosphor Icons, Zod, Node test runner, jsdom, Rust 2024 edition, platform storage APIs

**Spec:** `docs/specs/full-implementation-2026-08-25.md`

## Constraints

- Preserve `contextIsolation: true`, `sandbox: true`, and `nodeIntegration: false`.
- Expose named high-level operations only; never expose raw CDB or device-path access to the renderer.
- Do not enable a mutating protocol whose selector, descriptor, or compatible media format remains unproven.
- Keep passwords, derived keys, authorization blobs, and firmware bytes out of logs and persistence.
- Keep every hand-written file under 1,000 lines and document every function/method with JSDoc or Rust documentation.
- Treat source/build/runtime checks as distinct from physical-hardware proof.
- Use exact fixture/golden tests before production behavior; watch each new test fail for the intended missing behavior before implementation.
- Do not package, sign, publish, deploy, or release in these implementation phases.

---

### Phase 1: Application shell and safety boundary

**Plan:** `docs/plans/application-shell-2026-08-25.md`

**Produces:** The approved dashboard in a real Electron window, local Phosphor/font assets, device/no-device fixtures, localization engine, typed preload IPC, operation locking, safety policy, and a supervised no-device service boundary.

**Exit gate:** `npm test`, `npm run format:check`, and `env -u ELECTRON_RUN_AS_NODE npm run smoke` pass; the real window is visually reviewed at `1024 x 768` and `1440 x 900`.

### Phase 2: Native protocol and service core

**Plan:** `docs/plans/native-core-2026-08-25.md`

**Consumes:** Phase 1 operation/device contracts.

**Produces:** The Rust service package, exact CDB builders/parsers, sense handling, firmware validator/chunker, evidence registry, deterministic fake transport, operation state machines, framed service protocol, and CLI surface.

**Exit gate:** Node contract tests and `cargo test --manifest-path native/rdx-service/Cargo.toml` pass without a device.

### Phase 3: Platform transports and host operations

**Plan:** `docs/plans/platform-hardware-2026-08-25.md`

**Consumes:** Phase 2 transport/host traits and service protocol.

**Produces:** Native Windows, Linux, and macOS discovery/pass-through adapters; safe mount/eject/format and Windows drive-letter integration; Electron-to-native service handshake; platform capability diagnostics.

**Exit gate:** Native compile/unit checks pass on each target OS, the Electron no-device runtime reports the correct platform capability state, and no hardware success is claimed.

### Phase 4: Complete feature workflows and verification

**Plan:** `docs/plans/feature-completion-2026-08-25.md`

**Consumes:** All earlier device, operation, service, and platform interfaces.

**Produces:** All 25 documented capability groups, eight languages, tray/CLI/help/support/update behavior, evidence-gated security workflows, complete UI states, cross-platform verification scripts, and the pending physical-hardware acceptance matrix.

**Exit gate:** Full Node/Rust/format/smoke/visual suites pass, focused Git diff contains only scoped files, and the handoff distinguishes fixture-tested, native-built, runtime-verified, evidence-incomplete, and hardware-unverified behavior.

## Execution Order

- [ ] **Step 1: Execute Phase 1 and review its independently runnable dashboard**

Run the Phase 1 plan from top to bottom and commit only after every task's red-green cycle passes.

- [ ] **Step 2: Execute Phase 2 and review protocol/service fixtures**

Do not begin a native platform adapter before exact portable builders, parsers, errors, and fake-transport operations are green.

- [ ] **Step 3: Execute Phase 3 on native target hosts**

Platform support requires a native compile/test result from each operating system. Cross-compilation alone is supplemental evidence.

- [ ] **Step 4: Execute Phase 4 in increasing risk order**

Implement read-only/support behavior, diagnostics, safe eject/configuration, firmware, and then proven security/destructive workflows. Leave incomplete protocol writes disabled.

- [ ] **Step 5: Perform final integrated verification**

Run:

```sh
npm test
npm run native:test
npm run format:check
env -u ELECTRON_RUN_AS_NODE npm run smoke
git status --short
git diff --check
```

Expected: every command exits `0`; status/diff contain only the reviewed implementation and documented local visual-companion artifacts remain untracked/ignored.
