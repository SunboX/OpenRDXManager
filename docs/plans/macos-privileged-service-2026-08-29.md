<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# macOS privileged service implementation plan — 2026-08-29

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Make the packaged Electron app register an authenticated root launch daemon, report exact service prerequisites, and safely connect to mounted RDX hardware on current macOS.

**Architecture:** Electron main uses a fixed N-API bridge to `SMAppService`, while the sandboxed renderer sees only strict setup/capability state and opaque candidate tokens. The embedded launchd helper owns root USB access, authenticates the signed manager at accept time, and performs an explicit Disk Arbitration unmount before validating a mounted RDX candidate.

**Technology:** Electron 44, Node.js 22.16.0, native ESM, Zod 4, Node test runner, Rust 1.85+, C17, Objective-C++, N-API, ServiceManagement, Security.framework, IOKit, Disk Arbitration, launchd

**Spec:** `docs/specs/macos-privileged-service-2026-08-29.md`

The signing and shared endpoint requirements below describe the original signed
mode. The [locally trusted installation specification](../specs/locally-trusted-installation-2026-10-12.md)
defines the later installer mode with its separate fixed service label and socket.

## Constraints

- Work on `main` because the user explicitly rejected an isolated worktree.
- Preserve `contextIsolation: true`, `sandbox: true`, and `nodeIntegration: false`.
- Keep privileged hardware access in `openrdx-hardware`; never expose paths, CDBs, or arbitrary native arguments to the renderer.
- Auto Scan never unmounts media; only an explicit confirmed preparation intent may request a normal unmount.
- Packaged production connects only to `/var/run/openrdx-hardware.sock`; it never falls back to a child service.
- Use the existing Phosphor icon package and all eight locale catalogs.
- Use the explicit Node 22.16.0 installation and put Homebrew Cargo tools before rustup shims.
- Sign with an explicitly selected local identity; never guess between identities.
- Do not publish, push, notarize, or distribute artifacts.
- Keep every hand-written file below 1,000 lines and document every function and method.

---

### Task 1: Truthful service capability propagation

**Files:**

- Modify: `src/shared/schemas.mjs`
- Modify: `src/main/service-runtime.mjs`
- Modify: `src/renderer/service-binding.mjs`
- Modify: `src/renderer/store.mjs`
- Modify: `src/renderer/views/shell-view.mjs`
- Test: `test/service-runtime.test.mjs`
- Test: `test/service-binding.test.mjs`
- Test: `test/task6-final-hotplug.test.mjs`

**Interfaces:**

- Consumes: `DeviceServiceClient#getPlatformCapability()` and `DeviceServiceClient#hasPrivilege()`.
- Produces: renderer service state `{status:'ready', mode, privileged, hardwareReady, hardwareVerified, platformCapability}` and `isDiscoveryAvailable(service)`.

- [ ] **Step 1: Write failing schema/runtime tests**

    Update ready-event and list-response literals to require:

    ```js
    privileged: false,
    platformCapability: { state: 'insufficient-permission', reason: 'privileged-service-unavailable' }
    ```

    Assert a runtime ready event and `devices.list()` preserve those exact values.

- [ ] **Step 2: Run RED**

    Run:

    ```sh
    node --test test/service-runtime.test.mjs test/service-binding.test.mjs test/task6-final-hotplug.test.mjs
    ```

    Expected: FAIL because strict schemas or renderer state omit the two fields.

- [ ] **Step 3: Implement minimal propagation**

    Export the existing capability schema as `platformCapabilitySchema`, add the two fields to strict service/list schemas, publish them from `service-runtime.mjs`, dispatch them in `service-binding.mjs`, and validate/store them in `store.mjs`.

    Add:

    ```js
    export function isDiscoveryAvailable(service) {
        return service?.status === 'ready' && service.mode === 'native' && service.privileged === true && service.platformCapability?.state === 'available'
    }
    ```

    Use it for every scan control and no-device state.

- [ ] **Step 4: Run GREEN and full Node regression**

    Run the focused command, then `npm test` under Node 22.16.0.

- [ ] **Step 5: Commit**

    Stage only Task 1 files and commit `fix: expose hardware service prerequisites`.

### Task 2: Fixed macOS ServiceManagement bridge

**Files:**

- Create: `native/service-management/macos/openrdx_service_management.mm`
- Create: `scripts/build-macos-service-management.mjs`
- Create: `src/main/macos-privileged-service.mjs`
- Modify: `scripts/build-runtime` integration in `package.json`
- Test: `test/macos-privileged-service.test.mjs`
- Test: `test/macos-service-management-build.test.mjs`

**Interfaces:**

- Produces native addon methods `status()`, `registerService()`, `unregisterService()`, and `openApprovalSettings()`, each accepting zero arguments.
- Produces `createMacOsPrivilegedServiceController({addon, isPackaged, platform})` with `getStatus()`, `register()`, `unregister()`, and `openApprovalSettings()`.

- [ ] **Step 1: Write failing controller tests**

    Use a complete in-memory native adapter and assert:

    ```js
    assert.deepEqual(controller.getStatus(), { state: 'requires-approval' })
    assert.deepEqual(await controller.register(), { ok: false, reason: 'requires-approval' })
    assert.deepEqual(await controller.openApprovalSettings(), { ok: true })
    ```

    Assert non-macOS and unpackaged runtimes return `{state:'not-applicable'}` and never invoke the addon. Assert malformed addon output becomes `invalid-native-response`.

- [ ] **Step 2: Run controller RED**

    Run `node --test test/macos-privileged-service.test.mjs` and require module-not-found failure.

- [ ] **Step 3: Implement the pure JavaScript controller**

    Keep the closed states `not-applicable`, `not-registered`, `enabled`, `requires-approval`, `not-found`, `invalid-signature`, and `registration-failed`. No method accepts caller paths or native labels.

- [ ] **Step 4: Run controller GREEN**

    Re-run the focused controller test.

- [ ] **Step 5: Write failing addon build/behavior test**

    Build into a temporary controlled directory, load the `.node` file with `createRequire`, assert all four zero-argument exports exist, assert an unexpected argument throws `TypeError`, and assert `status()` returns exactly one closed state.

- [ ] **Step 6: Run addon RED**

    Run `node --test test/macos-service-management-build.test.mjs`; expect failure because the builder and source do not exist.

- [ ] **Step 7: Implement the N-API addon and builder**

    Compile Objective-C++ with ARC, `-bundle`, `-undefined dynamic_lookup`, Node headers, Foundation, and ServiceManagement. Hard-code only `com.openrdx.hardware.plist`. Map `SMAppServiceStatus` and `SMAppServiceErrorDomain` to the closed values; return no native description strings.

- [ ] **Step 8: Run addon GREEN**

    Run the focused build test and `npm run format:check`.

- [ ] **Step 9: Commit**

    Stage Task 2 files and commit `feat: add macOS service management bridge`.

### Task 3: Signed macOS application bundle

**Files:**

- Create: `scripts/package-macos.mjs`
- Create: `test/macos-package.test.mjs`
- Modify: `src/main/device-service-transport.mjs`
- Modify: `package.json`
- Modify: `native/rdx-service/resources/macos/com.openrdx.hardware.plist`
- Modify: `native/rdx-service/resources/macos/README.md`

**Interfaces:**

- Produces `getMacOsPackagePaths({projectRoot, outputRoot})` and `packageMacOsApplication({projectRoot, outputRoot, signingIdentity})`.
- Produces `npm run package:macos -- --signing-identity <SHA-1-or-name>`.
- Changes packaged macOS service executable resolution to `Contents/Library/LaunchServices/openrdx-hardware`.

- [ ] **Step 1: Write failing package-path and assembly tests**

    Build against a synthetic Electron bundle and fake command executor. Assert the result has one helper at `Contents/Library/LaunchServices/openrdx-hardware`, one daemon plist at `Contents/Library/LaunchDaemons/com.openrdx.hardware.plist`, one addon under `Contents/Resources/native/macos`, `Contents/Resources/app/package.json`, and no duplicate helper under Resources.

    Assert empty signing identity, path escape, symlinked inputs, missing artifacts, or failed signing command abort before publishing the final bundle.

- [ ] **Step 2: Run package RED**

    Run `node --test test/macos-package.test.mjs`; expect module-not-found failure.

- [ ] **Step 3: Implement deterministic assembly**

    Copy Electron with `/usr/bin/ditto` into a private temporary sibling, rename the executable and helper bundles, update all bundle identifiers and executable names using `/usr/libexec/PlistBuddy`, copy only application runtime source/assets/dependencies, helper, addon, and plist, then sign nested code inside-out and atomically rename to the final output.

    Validate with:

    ```sh
    /usr/bin/codesign --verify --deep --strict --verbose=2 OpenRDXManager.app
    /usr/bin/codesign -d -r- OpenRDXManager.app
    ```

- [ ] **Step 4: Run package GREEN**

    Run the focused test and `npm run format:check`.

- [ ] **Step 5: Commit**

    Stage Task 3 files and commit `build: package signed macOS application`.

### Task 4: Embedded team-pinned helper authentication

**Files:**

- Modify: `native/rdx-service/src/endpoint.rs`
- Modify: `native/rdx-service/src/bin/openrdx-hardware.rs`
- Modify: `scripts/build-native-service.mjs`
- Test: `native/rdx-service/tests/endpoint_access.rs`
- Test: `test/native-service-build.test.mjs`

**Interfaces:**

- Produces `embedded_macos_manager_designated_requirement() -> Result<String, EndpointAccessError>` from compile-time `OPENRDX_MANAGER_TEAM_ID`.
- The package build passes the exact team ID extracted from the selected signing identity to Cargo.

- [ ] **Step 1: Write failing Rust and build tests**

    Assert a ten-character uppercase/digit team produces the exact manager requirement, while empty, lowercase, short, long, punctuation, and ad-hoc builds fail closed. Assert the Node builder passes only validated `OPENRDX_MANAGER_TEAM_ID` and rejects invalid values.

- [ ] **Step 2: Run RED**

    Run the exact endpoint test and `node --test test/native-service-build.test.mjs`; expect missing embedded-requirement behavior.

- [ ] **Step 3: Implement compile-time binding**

    Use `option_env!("OPENRDX_MANAGER_TEAM_ID")`; do not read a runtime environment variable. The packaged launchd mode loads the embedded requirement. Development direct CLI and fixtures retain their explicit test paths but cannot acquire packaged endpoint authority.

- [ ] **Step 4: Run GREEN and native checks**

    Run the focused tests and `npm run native:check` with Homebrew Cargo tools first in `PATH`.

- [ ] **Step 5: Commit**

    Stage Task 4 files and commit `fix: pin macOS manager to embedded signing team`.

### Task 5: Setup IPC and exact renderer recovery states

**Files:**

- Modify: `src/shared/ipc-contract.mjs`
- Modify: `src/shared/schemas.mjs`
- Modify: `src/preload-api.mjs`
- Modify: `src/main/ipc-controller.mjs`
- Modify: `src/main.mjs`
- Modify: `src/renderer/service-binding.mjs`
- Modify: `src/renderer/store.mjs`
- Modify: `src/renderer/app-controller.mjs`
- Modify: `src/renderer/views/shell-view.mjs`
- Modify: `src/locales/{en,de,es,fr,it,ja,pt,zh}.mjs`
- Test: `test/ipc-controller.test.mjs`
- Test: `test/preload-api.test.mjs`
- Test: `test/service-binding.test.mjs`
- Test: `test/renderer-status-dom.test.mjs`
- Test: `test/locales-complete.test.mjs`

**Interfaces:**

- Produces preload methods `service.getSetup()`, `service.register()`, and `service.openApprovalSettings()`.
- Produces setup response `{ok:true, state}` or strict bridge failure.

- [ ] **Step 1: Write failing boundary and DOM tests**

    Assert unknown request keys and untrusted senders are rejected; non-macOS routes are not applicable; the renderer prioritizes setup-required, approval-required, enabled-but-unreachable, and insufficient-permission copy ahead of candidate diagnostics; the top badge and central card agree.

- [ ] **Step 2: Run RED**

    Run the five focused Node suites and require missing channels/methods/state failures.

- [ ] **Step 3: Implement the strict setup boundary and UI**

    Register only the three fixed channels. Instantiate the controller only in Electron main and load the addon from `process.resourcesPath/native/macos/openrdx-service-management.node`. After successful registration or settings return, refresh status and restart/reconnect the service runtime without spawning a child.

    Render existing Phosphor `shield-check`, `gear`, `arrow-clockwise`, and `sliders-horizontal` icons with localized action labels.

- [ ] **Step 4: Run GREEN and renderer regression**

    Run focused tests, `npm test`, `npm run test:compact`, and `npm run test:visual`.

- [ ] **Step 5: Commit**

    Stage Task 5 files and commit `feat: guide macOS hardware service setup`.

### Task 6: Opaque mounted-candidate preparation

**Files:**

- Modify: `native/rdx-service/src/platform/macos.rs`
- Modify: `native/rdx-service/src/service/hardware/discovery.rs`
- Modify: `native/rdx-service/src/service/protocol.rs`
- Modify: `src/main/device-service-wire.mjs`
- Modify: `src/main/device-service-client.mjs`
- Modify: `src/shared/ipc-contract.mjs`
- Modify: `src/shared/schemas.mjs`
- Modify: `src/preload-api.mjs`
- Modify: `src/main/ipc-controller.mjs`
- Modify: `src/main/service-runtime.mjs`
- Modify: `src/renderer/app-controller.mjs`
- Modify: `src/renderer/views/shell-view.mjs`
- Modify: `src/locales/{en,de,es,fr,it,ja,pt,zh}.mjs`
- Test: `native/rdx-service/tests/macos_bridge.rs`
- Test: `native/rdx-service/tests/service_protocol.rs`
- Test: `test/device-service-client.test.mjs`
- Test: `test/ipc-controller.test.mjs`
- Test: `test/renderer-status-dom.test.mjs`

**Interfaces:**

- Produces candidate outcome `{reason:'media-mounted', count:1, preparationToken:'candidate:<opaque>'}` only for one exact current candidate.
- Produces service method `candidate-prepare` with request `{preparationToken}` and result `{ok:true}` or a closed failure reason.

- [ ] **Step 1: Write failing token and state-transition tests**

    Assert Auto Scan never unmounts. Assert a mounted, prefiltered single candidate gets one generation-bound token. Assert a confirmed request revalidates identity, normally unmounts, acquires SCSI, validates INQUIRY, and publishes a device. Assert token reuse, expiry, scan-generation drift, serial/topology drift, ambiguity, unmount denial, and device removal fail without touching a different disk.

- [ ] **Step 2: Run RED**

    Run the focused Rust service tests and three Node suites; require missing method/token failures.

- [ ] **Step 3: Implement minimal service preparation state**

    Store tokens only in service memory with a 60-second lifetime and current discovery generation. Bind each token to retained candidate authority and a path-free media fingerprint. Consume before unmount and return a fresh scan result only after exact RDX identity validation.

- [ ] **Step 4: Implement renderer confirmation flow**

    Show “Unmount and connect” only for the exact token-bearing outcome. Use the existing confirmation dialog and operation lock. Do not expose or interpolate a native path.

- [ ] **Step 5: Run GREEN and full native/Node regression**

    Run focused tests, `npm run native:quality`, `npm test`, `npm run test:compact`, and `npm run test:visual`.

- [ ] **Step 6: Commit**

    Stage Task 6 files and commit `feat: prepare mounted macOS RDX candidates`.

### Task 7: Signed runtime and physical hardware acceptance

**Files:**

- Modify: `docs/verification/hardware-acceptance.md`
- Modify: `docs/verification/implementation-verification.md`
- Modify: `docs/verification/platform-verification.md`

**Interfaces:**

- Consumes all previous artifacts and the connected disposable hardware.
- Produces exact signed-app, service, device, operation, and cleanup evidence.

- [ ] **Step 1: Build and sign the local app**

    Select the already identified Apple Development identity explicitly, extract and validate Team ID `7UXAQ487HP`, build the helper with that embedded team, package the app, and verify every nested signature and designated requirement.

- [ ] **Step 2: Register through the app**

    Launch the packaged app and invoke its setup action. If macOS requires approval, open the standard System Settings pane and wait for the user-owned approval. Never collect credentials in terminal or app UI.

- [ ] **Step 3: Prove privileged handshake and mounted state**

    Require `{privileged:true, platformCapability:{state:'available'}}`. With the cartridge mounted, require `media-mounted` and the explicit preparation action rather than `candidate-validation-failed`.

- [ ] **Step 4: Connect and verify the physical device**

    Run “Unmount and connect” and require vendor `TANDBERG`, product `RDX`, serial `007820746632`, firmware `0227`, and a nonempty opaque `rdx:` device ID.

- [ ] **Step 5: Run bounded hardware operations**

    Run status refresh and Self first. Run LED with automatic off cleanup, write/read with independent file cleanup, safe eject, reinsert, and exFAT format only after fresh identity/capacity confirmation on the empty disposable cartridge. Record host-reported and visually observed evidence separately.

- [ ] **Step 6: Run the complete verification gate**

    Run:

    ```sh
    npm run format:check
    npm run native:quality
    npm test
    npm run test:compact
    npm run test:visual
    env -u ELECTRON_RUN_AS_NODE npm run smoke
    npm run verify:native-platform
    git diff --check
    git status --short
    ```

    Inspect the generated native-platform JSON and the real packaged Electron window. Do not infer hardware success from process exit.

- [ ] **Step 7: Record evidence and commit**

    Update only the three verification documents with exact command results, timestamps, macOS build, app commit, service/signature state, device identity, operation outcomes, and cleanup. Stage the implementation plus existing related hardware changes deliberately, inspect the staged diff, and commit with a focused Conventional Commit. Do not push or publish.
