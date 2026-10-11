<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Application shell implementation plan — 2026-08-25

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Replace the blank renderer with the approved responsive dashboard and establish the typed, testable Electron safety boundary used by every later hardware feature.

**Architecture:** Keep the renderer as native browser ESM with a small store and focused view modules. A frozen preload API sends only schema-validated high-level requests to main; main owns device-service supervision, operation locking, safety policy, logs, and lifecycle.

**Technology:** Electron 44, Node.js native ESM, HTML/CSS, Phosphor Icons, Oxanium, Inter, Zod, jsdom, Node test runner

**Spec:** `docs/specs/full-implementation-2026-08-25.md`

## Constraints

- Preserve the existing Electron security defaults and local-only renderer.
- Bundle Phosphor/font assets locally; do not load a CDN or remote font.
- Document every new function/method with JSDoc.
- Keep renderer state serializable and free of device paths, passwords, keys, and raw commands.
- Every feature gate shows a stable reason code; disabled actions never silently invoke fallback behavior.
- Keep each hand-written file below 1,000 lines.

---

### Task 1: Lock the application dependencies and resource contract

**Files:**

- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `.gitignore`
- Modify: `test/project-structure.test.mjs`

**Interfaces:**

- Consumes: existing npm package metadata.
- Produces: locally installed `@fontsource/inter`, `@fontsource/oxanium`, `@phosphor-icons/web`, `zod`, and test-only `jsdom`; ignored `.superpowers/` visual-companion state.

- [ ] **Step 1: Write the failing dependency/resource test**

Add assertions that production dependencies contain the four runtime packages, `jsdom` is a dev dependency, and `.gitignore` contains `.superpowers/`.

```js
assert.equal(pkg.dependencies['@phosphor-icons/web'], '^2.1.2')
assert.ok(pkg.dependencies['@fontsource/inter'])
assert.ok(pkg.dependencies['@fontsource/oxanium'])
assert.ok(pkg.dependencies.zod)
assert.ok(pkg.devDependencies.jsdom)
assert.match(gitignore, /^\.superpowers\/$/m)
```

- [ ] **Step 2: Run the focused test and observe the intended failure**

Run: `npm test -- test/project-structure.test.mjs`

Expected: FAIL because the dependencies and ignore rule do not exist.

- [ ] **Step 3: Install dependencies and add the ignore rule**

Run:

```sh
npm install @fontsource/inter @fontsource/oxanium @phosphor-icons/web@^2.1.2 zod
npm install --save-dev jsdom
```

Use `apply_patch` to append `.superpowers/` under tool caches in `.gitignore`.

- [ ] **Step 4: Verify the focused test**

Run: `npm test -- test/project-structure.test.mjs`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add package.json package-lock.json .gitignore test/project-structure.test.mjs
git commit -m "build: add local dashboard assets"
```

### Task 2: Define shared device, capability, and operation contracts

**Files:**

- Create: `src/shared/contracts.mjs`
- Create: `src/shared/schemas.mjs`
- Create: `test/contracts.test.mjs`

**Interfaces:**

- Produces: `CapabilityState`, `OperationKind`, `RiskClass`, `createDeviceSnapshot(input)`, `deviceSnapshotSchema`, `operationRequestSchema`, and `operationEventSchema`.
- Consumes: no Electron APIs.

- [ ] **Step 1: Write failing contract tests**

```js
test('rejects renderer supplied device paths and unknown operation keys', () => {
    const request = {
        kind: 'self-test',
        deviceId: 'rdx:7810544062',
        deviceRevision: 4,
        osPath: '/dev/sg4'
    }
    assert.equal(operationRequestSchema.safeParse(request).success, false)
})

test('normalizes a no-media RDX snapshot', () => {
    const snapshot = createDeviceSnapshot({
        id: 'rdx:7810544062',
        revision: 4,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: '7810544062',
        media: null,
        capabilities: { 'self-test': { state: 'available' } }
    })
    assert.equal(snapshot.mediaState, 'no-media')
    assert.equal(Object.isFrozen(snapshot), true)
})
```

- [ ] **Step 2: Run and confirm missing-module failure**

Run: `npm test -- test/contracts.test.mjs`

Expected: FAIL because the shared contract modules do not exist.

- [ ] **Step 3: Implement exact enums, factories, and strict Zod schemas**

Define operation kinds for scan, status refresh, access enable/disable, credential management, self/LED/write-read tests, firmware update, drive letter, format, drive mode, SATA mode, and eject. Use `.strict()` on request objects and freeze normalized snapshots.

- [ ] **Step 4: Run focused and full tests**

Run: `npm test -- test/contracts.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/shared test/contracts.test.mjs
git commit -m "feat: define device operation contracts"
```

### Task 3: Create fixture state and renderer store

**Files:**

- Create: `src/renderer/fixture-state.mjs`
- Create: `src/renderer/store.mjs`
- Create: `test/renderer-store.test.mjs`

**Interfaces:**

- Consumes: `createDeviceSnapshot`.
- Produces: `createFixtureState({ mode })` and `createStore(initialState)` with `getState`, `dispatch`, and `subscribe`.

- [ ] **Step 1: Write failing state tests**

```js
test('selecting a device preserves an existing operation lock', () => {
    const store = createStore(createFixtureState({ mode: 'one-device' }))
    store.dispatch({ type: 'operation/started', operationId: 'op-1', kind: 'firmware-update' })
    store.dispatch({ type: 'device/select', deviceId: 'rdx:7810544062' })
    assert.equal(store.getState().activeOperation.id, 'op-1')
})

test('no-device fixture exposes a ready service and empty list', () => {
    const state = createFixtureState({ mode: 'no-device' })
    assert.equal(state.service.status, 'ready')
    assert.deepEqual(state.devices, [])
})
```

- [ ] **Step 2: Run and observe the missing-store failure**

Run: `npm test -- test/renderer-store.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement immutable reducer/store behavior and documented fixtures**

Use the manual screenshot identity values only as clearly marked fixture data. Include one-device, no-device, service-unavailable, busy, and operation-failed states.

- [ ] **Step 4: Run the focused tests**

Run: `npm test -- test/renderer-store.test.mjs`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/renderer/fixture-state.mjs src/renderer/store.mjs test/renderer-store.test.mjs
git commit -m "feat: add renderer device state store"
```

### Task 4: Render the approved dashboard and status workspace

**Files:**

- Modify: `src/index.html`
- Modify: `src/renderer.mjs`
- Create: `src/renderer/app-controller.mjs`
- Create: `src/renderer/views/shell-view.mjs`
- Create: `src/renderer/views/status-view.mjs`
- Create: `src/styles/tokens.css`
- Create: `src/styles/base.css`
- Create: `src/styles/layout.css`
- Create: `src/styles/components.css`
- Create: `src/styles/responsive.css`
- Create: `test/renderer-dom.test.mjs`

**Interfaces:**

- Consumes: renderer store snapshots.
- Produces: `mountApplication(root, options)`, `renderShell(state)`, and `renderStatusView(device)`.

- [ ] **Step 1: Write failing DOM behavior tests**

```js
test('renders the four original management areas and exact selected device', () => {
    const dom = createDashboardDom(createFixtureState({ mode: 'one-device' }))
    const labels = [...dom.window.document.querySelectorAll('[role="tab"]')].map((node) => node.textContent.trim())
    assert.deepEqual(labels, ['Status', 'Encryption', 'Tests', 'Utilities'])
    assert.match(dom.window.document.querySelector('main').textContent, /RDX QuikStor USB3\+ External/)
})

test('renders actionable no-device guidance without a manage action', () => {
    const dom = createDashboardDom(createFixtureState({ mode: 'no-device' }))
    assert.match(dom.window.document.body.textContent, /No RDX drives detected/)
    assert.equal(dom.window.document.querySelector('[data-action="manage-device"]'), null)
})
```

- [ ] **Step 2: Run and confirm the blank renderer fails**

Run: `npm test -- test/renderer-dom.test.mjs`

Expected: FAIL because the renderer has no dashboard.

- [ ] **Step 3: Implement semantic HTML and approved visual tokens**

Load local font/Icon CSS from `node_modules`, mount into `<div id="app">`, and implement the approved device rail, top bar, status cards, capacity bar, detailed drive/cartridge panels, command rail, activity list, service/no-device/error states, and four tabs. Use `ph-duotone` for feature categories and `ph` regular icons for routine controls.

- [ ] **Step 4: Run DOM and full tests**

Run: `npm test -- test/renderer-dom.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/index.html src/renderer.mjs src/renderer src/styles test/renderer-dom.test.mjs
git commit -m "feat: build OpenRDXManager dashboard"
```

### Task 5: Add localization engine and English catalog

**Files:**

- Create: `src/renderer/i18n.mjs`
- Create: `src/locales/en.mjs`
- Create: `test/i18n.test.mjs`
- Modify: renderer views from Task 4

**Interfaces:**

- Produces: `createTranslator(catalog, fallbackCatalog)` with `t(key, params)` and `supportedLanguageCodes`.
- Consumes: message keys from all renderer views.

- [ ] **Step 1: Write failing translation tests**

```js
test('falls back to English and interpolates bounded values', () => {
    const t = createTranslator({}, englishCatalog)
    assert.equal(t('devices.count', { count: 2 }), '2 RDX devices')
    assert.equal(t('missing.key'), '[missing.key]')
})
```

- [ ] **Step 2: Run and observe failure**

Run: `npm test -- test/i18n.test.mjs`

Expected: FAIL because the engine/catalog do not exist.

- [ ] **Step 3: Implement the engine and replace hard-coded UI copy with keys**

Reject prototype-path keys, coerce only string/number parameters, and keep raw vendor/model strings untranslated.

- [ ] **Step 4: Run i18n, DOM, and full tests**

Run: `npm test -- test/i18n.test.mjs test/renderer-dom.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/locales src/renderer/i18n.mjs src/renderer/views test/i18n.test.mjs test/renderer-dom.test.mjs
git commit -m "feat: add localized renderer copy"
```

### Task 6: Add the narrow preload API and validated main IPC

**Files:**

- Create: `src/preload.mjs`
- Create: `src/main/ipc-controller.mjs`
- Create: `src/main/safety-policy.mjs`
- Modify: `src/renderer.mjs`
- Modify: `src/renderer/app-controller.mjs`
- Modify: `src/renderer/intent-adapter.mjs`
- Modify: `src/main.mjs`
- Modify: `src/window-options.mjs`
- Modify: `test/renderer-dom.test.mjs`
- Create: `test/preload-contract.test.mjs`
- Create: `test/safety-policy.test.mjs`
- Modify: `test/window-options.test.mjs`

**Interfaces:**

- Produces: frozen `window.openRdx` API and `registerIpcHandlers({ ipcMain, services })`.
- Consumes: strict shared schemas, `evaluateOperation(request, context)`, and
  the renderer intent adapter established by Task 4.

- [ ] **Step 1: Write failing allow/reject tests**

```js
test('preload exposes named intents and no raw transport', () => {
    assert.deepEqual(Object.keys(api).sort(), ['app', 'devices', 'files', 'logs', 'operations', 'settings', 'support', 'updates'])
    assert.equal('sendCdb' in api, false)
})

test('safety policy rejects stale device revisions before dispatch', () => {
    const result = evaluateOperation({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 2 }, { device: { id: 'rdx:1', revision: 3 }, activeOperation: null })
    assert.equal(result.reason, 'stale-device-revision')
})
```

- [ ] **Step 2: Run and confirm missing API/policy failures**

Run: `npm test -- test/preload-contract.test.mjs test/safety-policy.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement preload, IPC registration, safety policy, renderer binding, and preload window option**

Resolve the preload path with URL-safe helpers, validate every request again in main, freeze public API objects, validate unsubscribe callbacks, and reject unknown senders/channels.
Bind only the Task 4 high-level renderer intents to the frozen preload API;
retain the safely disabled, truth-labelled renderer default whenever the bridge
is absent or an intent is not explicitly supported. Do not add any renderer
escape hatch for paths, raw commands, or channel names.

- [ ] **Step 4: Run focused/full tests**

Run: `npm test -- test/preload-contract.test.mjs test/safety-policy.test.mjs test/window-options.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/preload.mjs src/main.mjs src/main src/window-options.mjs test
git commit -m "feat: add validated Electron bridge"
```

### Task 7: Supervise the device service and serialize operations

**Files:**

- Create: `src/main/device-service-client.mjs`
- Create: `src/main/operation-coordinator.mjs`
- Create: `src/main/event-logger.mjs`
- Create: `test/device-service-client.test.mjs`
- Create: `test/operation-coordinator.test.mjs`
- Create: `test/event-logger.test.mjs`

**Interfaces:**

- Produces: `DeviceServiceClient`, `OperationCoordinator`, and `EventLogger` named classes.
- Consumes: a line/framed transport factory so tests can use an in-memory child-process double.

- [ ] **Step 1: Write failing lifecycle, lock, and redaction tests**

```js
test('one active operation rejects a second device action', async () => {
    const coordinator = new OperationCoordinator({ dispatch: async () => new Promise(() => {}) })
    void coordinator.start(validSelfTest)
    await assert.rejects(() => coordinator.start(validEject), /operation-in-progress/)
})

test('event logger redacts secret-shaped fields before rotation', async () => {
    await logger.write({ event: 'authenticate', password: 'never-log-me', deviceId: 'rdx:1' })
    assert.doesNotMatch(await readCurrentLog(), /never-log-me/)
})
```

- [ ] **Step 2: Run and observe missing-class failures**

Run: `npm test -- test/device-service-client.test.mjs test/operation-coordinator.test.mjs test/event-logger.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement handshake state, bounded restart, operation events, and `_RDXManager.bak` rotation**

The initial service factory returns a deterministic no-device adapter until the Rust binary is introduced in Phase 2. Do not convert a missing native binary into a successful hardware-ready state.

- [ ] **Step 4: Run focused/full tests**

Run: `npm test -- test/device-service-client.test.mjs test/operation-coordinator.test.mjs test/event-logger.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add src/main test/device-service-client.test.mjs test/operation-coordinator.test.mjs test/event-logger.test.mjs
git commit -m "feat: supervise hardware operations"
```

### Task 8: Verify the real Electron shell visually

**Files:**

- Modify: `src/main.mjs`
- Modify: `src/window-options.mjs`
- Modify: `README.md`
- Modify: `test/project-structure.test.mjs`

**Interfaces:**

- Consumes: complete Phase 1 renderer and no-device service boundary.
- Produces: smoke mode that waits for renderer-ready plus service-handshake/no-device state before exiting.

- [ ] **Step 1: Extend the smoke contract test to require renderer readiness**

Assert that smoke success is emitted only after the main process receives the renderer-ready event and the service client has reached a terminal ready/unavailable handshake state.

- [ ] **Step 2: Run the focused test and observe the old early smoke behavior fail**

Run: `npm test -- test/project-structure.test.mjs`

Expected: FAIL until the readiness contract is implemented.

- [ ] **Step 3: Implement readiness and update README commands/state boundaries**

Set the window default to `1280 x 800` with a `1024 x 768` minimum, preserve macOS activate behavior, and document fixture/no-device versus real-device proof.

- [ ] **Step 4: Run automated and real-window verification**

```sh
npm test
npm run format
npm run format:check
env -u ELECTRON_RUN_AS_NODE npm run smoke
```

Launch the real app, inspect at `1024 x 768` and `1440 x 900`, and capture local screenshots for device, no-device, service-unavailable, busy, and failed-operation states. Expected: no clipping, remote resources, console errors, or inaccessible action labels.

- [ ] **Step 5: Commit**

```sh
git add src/main.mjs src/window-options.mjs README.md test/project-structure.test.mjs
git commit -m "test: verify dashboard runtime"
```
