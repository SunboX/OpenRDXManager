<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Feature completion implementation plan — 2026-08-25

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Complete all 25 documented feature groups on top of the verified Electron/native boundaries and finish integrated visual, runtime, and evidence-aware verification.

**Architecture:** Each workspace view renders capabilities from the selected device and starts only named operations through the coordinator. Reusable preflight/progress/result components make routine, critical, destructive, blocked, and hardware-unverified states consistent.

**Technology:** Native ESM renderer, Phosphor Icons, Zod IPC, Node test runner/jsdom, Rust operation service, local Markdown/PDF-derived help content

**Spec:** `docs/specs/full-implementation-2026-08-25.md`

## Constraints

- Implement documented UI behavior even when a real operation remains capability/evidence blocked; never make a blocked button look successful.
- Critical/destructive workflows repeat identity and state checks in main and native service.
- Passwords remain transient and redacted; no password fixture uses a real credential.
- One operation locks device selection, tabs, conflicting actions, and unsafe close.
- Every added function/method has JSDoc or Rust documentation and a focused test that failed first.
- Physical-device acceptance remains pending until the user attaches explicit test hardware and disposable media where needed.

---

### Task 1: Build reusable capability, operation, and confirmation UI

**Files:**

- Create: `src/renderer/components/capability-state.mjs`
- Create: `src/renderer/components/operation-drawer.mjs`
- Create: `src/renderer/components/progress-timeline.mjs`
- Create: `src/renderer/components/confirmation-dialog.mjs`
- Create: `src/renderer/components/result-panel.mjs`
- Create: `test/operation-components.test.mjs`

**Interfaces:**

- Produces: `renderCapabilityState`, `renderOperationDrawer`, `renderProgressTimeline`, `requestExactDeviceConfirmation`, and `renderOperationResult`.
- Consumes: shared capability/operation models and translated message keys.

- [ ] **Step 1: Write failing component tests**

```js
test('destructive confirmation requires the displayed cartridge identity', () => {
    const dialog = requestExactDeviceConfirmation({ risk: 'destructive', expected: '858601695580' })
    dialog.input.value = '7810544062'
    dialog.input.dispatchEvent(new Event('input'))
    assert.equal(dialog.confirmButton.disabled, true)
})

test('evidence incomplete state never renders an enabled action', () => {
    const node = renderCapabilityState({ state: 'evidence-incomplete', reason: 'security-selector-unproven' })
    assert.equal(node.querySelector('button:not([disabled])'), null)
})
```

- [ ] **Step 2: Run and observe missing-component failures**

Run: `npm test -- test/operation-components.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement accessible drawers, dialogs, progress, results, and lock banner**

Use Phosphor icons plus visible labels, focus trapping/restoration, Escape only when safe, reduced motion, live progress announcements, and exact reason/help copy.

- [ ] **Step 4: Run focused/full tests**

Run: `npm test -- test/operation-components.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/renderer/components test/operation-components.test.mjs
git commit -m "feat: add guided operation components"
```

### Task 2: Complete Encryption, password, permission, and authentication workflows

**Files:**

- Create: `src/renderer/views/encryption-view.mjs`
- Create: `src/renderer/workflows/protection-workflow.mjs`
- Create: `src/renderer/workflows/password-workflow.mjs`
- Create: `src/renderer/workflows/automatic-auth-workflow.mjs`
- Create: `test/encryption-workflows.test.mjs`
- Create: `native/rdx-service/src/operations/security.rs`
- Create: `native/rdx-service/tests/security_operations.rs`
- Create: `analysis/scripts/extract_security_selector_evidence.py`
- Reference: `docs/protocols/features/07-basic-password-protection.md`
- Create: `test/fixtures/security-selector-fixtures.json`
- Modify: `native/rdx-service/src/protocol/security.rs`

**Interfaces:**

- Produces: all documented security screen states and high-level `EnableAccess`, `DisableAccess`, `CreateCredential`, `ChangeCredential`, `DeleteCredential`, `ResetProtection`, `ConfigureProtection`, and automatic-association operations.
- Consumes: evidence registry, eight-slot model, proven descriptor/KDF fixtures, host volume encryption capability.

- [ ] **Step 1: Write failing UI/state/evidence tests**

```js
test('read-only credential disables writes but allows access enable', () => {
    const view = renderEncryptionView(readOnlyCredentialFixture())
    assert.equal(view.querySelector('[data-action="enable-access"]').disabled, false)
    assert.equal(view.querySelector('[data-permission="write"]').textContent.trim(), 'Not allowed')
})

test('AES configure stays blocked without proven compatible media format', () => {
    const view = renderEncryptionView(aesEvidenceIncompleteFixture())
    assert.match(view.textContent, /Compatible AES media layout is not yet proven/)
    assert.equal(view.querySelector('[data-action="configure-aes"]').disabled, true)
})
```

Write Rust tests that every security mutator returns `evidence-incomplete` until its exact selector/descriptor fixture is registered; proven authentication/KDF fixtures produce exact descriptors in zeroizing buffers.

- [ ] **Step 2: Run and observe missing workflow/operation failures**

Run: `npm test -- test/encryption-workflows.test.mjs && cargo test --manifest-path native/rdx-service/Cargo.toml --test security_operations`

Expected: FAIL.

- [ ] **Step 3: Perform focused evidence recovery before enabling each mutator**

Trace selector construction, descriptor flags, slot indexing, KDF parameters, and host volume calls from supplied Windows/macOS artifacts. Record the source function/address and regenerate any derived focused analysis through its source scripts. Add an immutable fixture and golden test for each proven operation; leave all others blocked.

- [ ] **Step 4: Implement complete UX and only proven native operations**

Include Basic/AES choice, plaintext warning, strength scale, reset policy, destructive consequences, enable/disable status, add/change/delete rows, unique names, one master plus seven slots, temporary-slot requirement, permissions, automatic SATA III association limits/write option/delete semantics, and reinsertion guidance. Zeroize password bytes after every terminal result.

- [ ] **Step 5: Run security and full suites**

Run: `npm test -- test/encryption-workflows.test.mjs && cargo test --manifest-path native/rdx-service/Cargo.toml --test security_operations && npm test && npm run native:test`

Expected: PASS; evidence registry and UI availability agree for every operation.

- [ ] **Step 6: Commit**

```sh
git add src/renderer/views/encryption-view.mjs src/renderer/workflows test/encryption-workflows.test.mjs native/rdx-service/src/operations/security.rs native/rdx-service/src/protocol/security.rs native/rdx-service/tests/security_operations.rs docs/protocols/features/07-basic-password-protection.md test/fixtures/security-selector-fixtures.json
git commit -m "feat: add evidence-gated RDX protection"
```

### Task 3: Complete diagnostics and Write/Read Test UI

**Files:**

- Create: `src/renderer/views/tests-view.mjs`
- Create: `src/renderer/workflows/test-workflow.mjs`
- Create: `test/diagnostic-workflows.test.mjs`
- Modify: native diagnostic/volume operations

**Interfaces:**

- Produces: Self Test, LED Test, and Write/Read Test cards, prerequisites, staged progress, pass/fail/cleanup evidence, and recommended two-pass self-test guidance.

- [ ] **Step 1: Write failing workflow tests**

```js
test('write-read test explains every unmet prerequisite', () => {
    const view = renderTestsView(unformattedReadOnlyMediaFixture())
    assert.match(view.textContent, /formatted cartridge/i)
    assert.match(view.textContent, /write access/i)
    assert.equal(view.querySelector('[data-action="write-read-test"]').disabled, true)
})
```

- [ ] **Step 2: Run and confirm missing view failure**

Run: `npm test -- test/diagnostic-workflows.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement Test view, stage mapping, LED cleanup result, and write/read file cleanup result**

Use the documented gray active/failure and green success semantics within accessible dark-theme colors; distinguish primary failure from cleanup failure.

- [ ] **Step 4: Run Node/Rust/full tests**

Run: `npm test -- test/diagnostic-workflows.test.mjs && npm run native:test && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/renderer/views/tests-view.mjs src/renderer/workflows/test-workflow.mjs test/diagnostic-workflows.test.mjs native/rdx-service/src/operations
git commit -m "feat: add RDX diagnostic workflows"
```

### Task 4: Complete Utilities and firmware UI

**Files:**

- Create: `src/renderer/views/utilities-view.mjs`
- Create: `src/renderer/workflows/firmware-workflow.mjs`
- Create: `src/renderer/workflows/format-workflow.mjs`
- Create: `src/renderer/workflows/mode-workflow.mjs`
- Create: `src/renderer/workflows/eject-workflow.mjs`
- Create: `test/utility-workflows.test.mjs`

**Interfaces:**

- Produces: safe/force eject, firmware, format, drive-letter, Fixed/Removable, and SATA mode cards plus exact preflight/progress/result flows.
- Consumes: platform and operation capability states from Phases 2-3.

- [ ] **Step 1: Write failing utility gating tests**

```js
test('firmware preflight rejects media and a mismatched image before transfer', () => {
    const view = renderUtilitiesView(firmwareBlockedFixture())
    assert.match(view.textContent, /Eject the cartridge/)
    assert.equal(view.querySelector('[data-action="start-firmware"]').disabled, true)
})

test('USB dock never offers SATA link setter', () => {
    const view = renderUtilitiesView(usbDockFixture())
    assert.match(view.querySelector('[data-feature="sata-mode"]').textContent, /SATA III docks only/)
})
```

- [ ] **Step 2: Run and observe missing utility view failure**

Run: `npm test -- test/utility-workflows.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement all utility cards and guided workflows**

Include documented extensions/product families, no-power-off and signed-downgrade warnings, cartridge-ejected requirements, available drive letters, NTFS default/exFAT quick format, exact-device destructive confirmation, current-mode no-op, recommended SATA default, SSD qualification, safe/force boundaries, and operation lock.

- [ ] **Step 4: Run utility/native/full tests**

Run: `npm test -- test/utility-workflows.test.mjs && npm run native:test && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/renderer/views/utilities-view.mjs src/renderer/workflows test/utility-workflows.test.mjs
git commit -m "feat: add RDX utility workflows"
```

### Task 5: Add logs, support summary, help, and update checking

**Files:**

- Create: `src/renderer/views/activity-view.mjs`
- Create: `src/renderer/views/help-view.mjs`
- Create: `src/main/support-summary-service.mjs`
- Create: `src/main/update-service.mjs`
- Create: `src/help/help-index.mjs`
- Create: `test/support-and-updates.test.mjs`
- Modify: `src/main/ipc-controller.mjs`

**Interfaces:**

- Produces: log toggle/filter/export, `RdxSystemSummary.txt`, local F1 help, About, Support, explicit/silent metadata check, historical compatibility/troubleshooting content.

- [ ] **Step 1: Write failing privacy and failure-boundary tests**

```js
test('support summary omits secrets and preserves documented device fields', async () => {
    const text = await service.generate(summaryFixtureWithSecrets())
    assert.doesNotMatch(text, /password|derivedKey|authorizationBlob/i)
    assert.match(text, /Firmware revision: 0283/)
})

test('invalid update metadata cannot offer an install action', async () => {
    await assert.rejects(() => updateService.parse('{"version":"2.0.0"}'), /unsigned-or-invalid-manifest/)
})
```

- [ ] **Step 2: Run and observe missing-service failures**

Run: `npm test -- test/support-and-updates.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement sanitized summary, help routing, logs, and signed/configured metadata checks**

Use a local help index sourced from the numbered docs, keep historical URLs informational, distinguish Manager versus firmware availability, and never auto-apply firmware from a network response.

- [ ] **Step 4: Run focused/full tests**

Run: `npm test -- test/support-and-updates.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/renderer/views src/main/support-summary-service.mjs src/main/update-service.mjs src/main/ipc-controller.mjs src/help test/support-and-updates.test.mjs
git commit -m "feat: add RDX support and update tools"
```

### Task 6: Complete all eight languages, settings, tray, and lifecycle

**Files:**

- Create: `src/locales/zh.mjs`
- Create: `src/locales/de.mjs`
- Create: `src/locales/fr.mjs`
- Create: `src/locales/it.mjs`
- Create: `src/locales/pt.mjs`
- Create: `src/locales/es.mjs`
- Create: `src/locales/ja.mjs`
- Create: `src/main/settings-service.mjs`
- Create: `src/main/tray-controller.mjs`
- Create: `test/locales-complete.test.mjs`
- Create: `test/tray-lifecycle.test.mjs`
- Modify: `src/main.mjs`

**Interfaces:**

- Produces: complete key-parity catalogs, `-l <code>`, persisted safe settings, tray summary/open/scan/eject/logging/Exit, sleep/wake refresh, close-during-operation warning.

- [ ] **Step 1: Write failing locale parity and lifecycle tests**

```js
test('all supported catalogs have exactly the English message keys', () => {
    for (const catalog of catalogs) {
        assert.deepEqual(Object.keys(catalog).sort(), Object.keys(englishCatalog).sort())
    }
})

test('sleep invalidates polling and never requests eject', async () => {
    await trayLifecycle.onSuspend()
    assert.equal(scanner.running, false)
    assert.equal(service.startedOperations.length, 0)
})
```

- [ ] **Step 2: Run and observe missing catalogs/services**

Run: `npm test -- test/locales-complete.test.mjs test/tray-lifecycle.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement reviewed translations, startup parsing, settings whitelist, and tray/lifecycle behavior**

Persist only language, Auto Scan, logging, update-check preference, window bounds, and last safe view. Invalid `-l` falls back to English. Tray safe eject is disabled unless exactly one selected ready device permits it.

- [ ] **Step 4: Run locale/lifecycle/full/smoke tests**

Run: `npm test -- test/locales-complete.test.mjs test/tray-lifecycle.test.mjs && npm test && env -u ELECTRON_RUN_AS_NODE npm run smoke`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/locales src/main/settings-service.mjs src/main/tray-controller.mjs src/main.mjs test/locales-complete.test.mjs test/tray-lifecycle.test.mjs
git commit -m "feat: complete localized desktop integration"
```

### Task 7: Add compatibility, troubleshooting, and hardware acceptance coverage

**Files:**

- Create: `src/renderer/views/compatibility-view.mjs`
- Create: `docs/verification/hardware-acceptance.md`
- Create: `test/feature-coverage.test.mjs`
- Modify: `README.md`

**Interfaces:**

- Produces: live capability explanation, historical vendor matrix, support diagnostic order, known limitations, and physical test checklist by OS/model/firmware/media/operation.

- [ ] **Step 1: Write failing 25-feature coverage test**

```js
test('every documented feature group maps to a route, operation, help entry, or platform-only state', () => {
    const covered = new Set(featureManifest.map((entry) => entry.documentNumber))
    assert.deepEqual(
        [...covered].sort((a, b) => a - b),
        Array.from({ length: 25 }, (_, index) => index + 1)
    )
})
```

- [ ] **Step 2: Run and observe incomplete manifest failure**

Run: `npm test -- test/feature-coverage.test.mjs`

Expected: FAIL until all 25 entries have concrete implementation/help/platform mappings.

- [ ] **Step 3: Implement manifest/view and acceptance matrix**

The matrix orders tests from read-only status through safe diagnostics/configuration to firmware/security/destructive disposable-media flows. Every row has an empty evidence field until real hardware execution supplies date, host, dock, firmware, cartridge, command/result, and operator confirmation.

- [ ] **Step 4: Run full coverage test**

Run: `npm test -- test/feature-coverage.test.mjs && npm test`

Expected: PASS with no fabricated hardware evidence.

- [ ] **Step 5: Commit**

```sh
git add src/renderer/views/compatibility-view.mjs docs/verification/hardware-acceptance.md README.md test/feature-coverage.test.mjs
git commit -m "docs: map complete RDX feature coverage"
```

### Task 8: Run integrated functional and visual verification

**Files:**

- Create: `test/integration/application-flow.test.mjs`
- Create: `docs/verification/implementation-verification.md`
- Modify: affected source/tests only when verification exposes a defect

**Interfaces:**

- Consumes: complete application.
- Produces: repeatable integrated proof and an honest final verification record.

- [ ] **Step 1: Write failing integrated fixture flow**

Test device selection, Status fields, disable/enable access UI, self/LED/write-read progress, safe eject, mode no-op, firmware preflight rejection, destructive confirmation rejection, logging export, summary generation, language switch, operation lock, service crash, and recovery.

- [ ] **Step 2: Run and observe the first unmet integrated behavior**

Run: `npm test -- test/integration/application-flow.test.mjs`

Expected: FAIL at the first missing integration; fix one behavior at a time while retaining the test-first failure evidence.

- [ ] **Step 3: Complete the integrated behavior and visual state matrix**

Inspect the real Electron window at `1024 x 768` and `1440 x 900` for no-device, ready device, no media, protected locked/unlocked, each feature area, active routine/critical/destructive operation, every disabled reason, success, failure, service unavailable, update unavailable, and all eight language layouts.

- [ ] **Step 4: Run the final verification commands**

```sh
npm test
npm run native:test
npm run native:fmt
npm run native:check
npm run format
npm run format:check
env -u ELECTRON_RUN_AS_NODE npm run smoke
git diff --check
git status --short
```

Expected: all checks exit `0`; documentation records current macOS no-device runtime proof and native Windows/Linux build results separately; hardware acceptance remains pending.

- [ ] **Step 5: Review focused diff and commit verification**

```sh
git add test/integration/application-flow.test.mjs docs/verification/implementation-verification.md
git commit -m "test: verify complete OpenRDXManager flows"
```
