<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# macOS 26 USB BOT transport implementation plan — 2026-08-29

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Make OpenRDXManager discover and control the connected TANDBERG RDX drive on macOS 26 when Apple's legacy `SCSITaskDeviceInterface` is unavailable, without weakening the existing Windows SPTI or Linux SG_IO implementations.

**Architecture:** Keep Electron sandboxing and the root-owned service boundary unchanged. The macOS native companion first uses the existing SCSI task interface; only `kIOReturnUnsupported` selects an `IOUSBHostObjectInitOptionsDeviceCapture` fallback for the same retained USB ancestor. A focused Objective-C bridge owns device capture and synchronous bulk pipes, while C validates the USB Bulk-Only Transport wire protocol and preserves attempted/not-attempted certainty, request-sense data, bounded timeouts, exact USB identity, clean release, and driver rematch.

**Technology:** Rust 1.85+, C17, Objective-C ARC, Apple IOKit, Disk Arbitration, IOUSBHost, Electron 44, Node.js 22.16.0

**Spec:** `docs/specs/full-implementation-2026-08-25.md`

## Constraints

- Preserve `contextIsolation: true`, `sandbox: true`, and `nodeIntegration: false`.
- Keep privileged hardware access in `openrdx-hardware`; never add raw paths, CDBs, or USB identifiers to renderer IPC.
- Admit only the exact retained TANDBERG/RDX candidate and its single mass-storage interface; reject ambiguous USB ancestry or endpoint topology.
- Require a clean Disk Arbitration unmount before capture; never force-unmount during background discovery.
- Bound CDBs to 16 bytes, transfer buffers to 4096 bytes, sense data to 252 bytes, and command timeouts to 300000 ms.
- Preserve dispatch certainty after CBW submission, validate CSW signature/tag/residue/status, clear a stalled bulk-IN endpoint once before the CSW retry, and issue bounded REQUEST SENSE after command failure.
- Destroy captured devices on every success/failure path so macOS resets and rematches its storage driver.
- Keep every hand-written file below 1000 lines and document every function or method.
- Treat host-side tests as software evidence only; physical verification requires the connected cartridge and exact command/result records.

---

### Task 1: USB BOT wire contract

**Files:**

- Modify: `native/rdx-service/native/macos/rdx_iokit.h`
- Modify: `native/rdx-service/native/macos/rdx_iokit_internal.h`
- Create: `native/rdx-service/native/macos/rdx_usb_bot.c`
- Modify: `native/rdx-service/native/macos/rdx_iokit_test.c`
- Modify: `native/rdx-service/macos-native/src/ffi.rs`
- Modify: `native/rdx-service/macos-native/src/test_support.rs`
- Modify: `native/rdx-service/macos-native/tests/portable_contract.rs`

**Interfaces:**

- Produces: `rdx_usb_bot_build_cbw`, `rdx_usb_bot_parse_csw`, and `usb_bot_wire_contract_is_enforced_for_test()`.
- Consumes: existing fixed-layout `rdx_macos_scsi_request` validation and native status mapping.

- [ ] **Step 1: Write the failing contract test**

    Add a test asserting that the observed INQUIRY CBW encodes signature `USBC`, a matching little-endian tag, transfer length 96, IN direction, LUN 0, CDB length 6, and CDB `12 00 00 00 60 00`; assert that a valid `USBS` CSW with residue 32 proves 64 transferred bytes and that signature, tag, residue, phase status, and reserved-bit corruption are rejected.

- [ ] **Step 2: Verify RED**

    Run:

    ```sh
    CARGO_TARGET_DIR=/tmp/openrdx-macos-bot cargo test --manifest-path native/rdx-service/Cargo.toml --features fixtures --test macos_bridge usb_bot -- --exact
    ```

    Expected: the new assertion fails because the test hook returns `false`.

- [ ] **Step 3: Implement the fixed wire codec**

    Encode and parse fixed byte arrays with explicit little-endian helpers. Reject a zero/over-16-byte CDB, transfer lengths above 4096, nonzero CBW reserved bits, CSW lengths other than 13, mismatched tags, residue above the requested transfer, and status outside 0 through 2.

- [ ] **Step 4: Verify GREEN**

    Rerun the exact command from Step 2 and expect PASS.

- [ ] **Step 5: Commit**

    ```sh
    git add native/rdx-service/native/macos/rdx_iokit.h native/rdx-service/native/macos/rdx_iokit_internal.h native/rdx-service/native/macos/rdx_usb_bot.c native/rdx-service/native/macos/rdx_iokit_test.c native/rdx-service/macos-native/src/ffi.rs native/rdx-service/macos-native/src/test_support.rs native/rdx-service/macos-native/tests/portable_contract.rs
    git commit -m "test: define macOS USB BOT wire contract"
    ```

### Task 2: Exact IOUSBHost capture and bulk transport

**Files:**

- Create: `native/rdx-service/native/macos/rdx_usb_host.m`
- Modify: `native/rdx-service/macos-native/build.rs`
- Modify: `native/rdx-service/native/macos/rdx_iokit.h`
- Modify: `native/rdx-service/native/macos/rdx_iokit_internal.h`
- Modify: `native/rdx-service/native/macos/rdx_iokit.c`
- Modify: `native/rdx-service/native/macos/rdx_iokit_scsi.c`
- Modify: `native/rdx-service/macos-native/src/ffi.rs`
- Modify: `native/rdx-service/macos-native/src/lib.rs`
- Modify: `native/rdx-service/macos-native/src/host.rs`
- Test: `native/rdx-service/macos-native/tests/portable_contract.rs`

**Interfaces:**

- Consumes: Task 1 CBW/CSW codec and the existing semantic `ScsiOperation` request layout.
- Produces: an opaque `rdx_macos_usb_bot_lease`, legacy-first acquisition fallback, synchronous `rdx_macos_execute_scsi` routing, and exact cleanup.

- [ ] **Step 1: Add failing fallback and cleanup tests**

    Extend test hooks so legacy plug-in `kIOReturnUnsupported` must select one fake USB capture, one mass-storage interface with exactly one bulk-IN and one bulk-OUT endpoint, a data phase, one CSW-stall clear/retry, and exactly one release. Assert that ambiguous ancestry, duplicate endpoints, wrong interface class/subclass/protocol, mismatched serial, timeout, and malformed CSW fail with the correct attempted flag.

- [ ] **Step 2: Verify RED**

    Run the focused macOS portable-contract tests and confirm the fallback assertions fail while existing legacy acquisition tests remain green.

- [ ] **Step 3: Implement the Objective-C bridge**

    Walk from the retained SCSI service to exactly one `IOUSBHostDevice`, copy bounded VID/PID/location/session/serial evidence, capture that exact service as root, configure value 1 with `matchInterfaces:NO`, locate one descendant interface `08/06/50`, open one bulk-IN and one bulk-OUT pipe, allocate IOUSBHost DMA buffers, and expose only fixed transfer/result structs to C. Use ARC and call `destroy` on both interface and device in every release path.

- [ ] **Step 4: Implement BOT execution and sense recovery**

    Route the existing semantic CDB builder through CBW, data, and CSW phases. Retry a stalled CSW once after `clearStallWithError`; on CSW command failure, issue REQUEST SENSE with a new tag and return SCSI CHECK CONDITION plus only the proven sense length. Mark failures after CBW admission as attempted.

- [ ] **Step 5: Verify GREEN**

    Run focused bridge and portable-contract tests, then `npm run native:check`.

- [ ] **Step 6: Commit**

    ```sh
    git add native/rdx-service/native/macos native/rdx-service/macos-native
    git commit -m "feat: add macOS IOUSBHost BOT fallback"
    ```

### Task 3: Mounted-media and session transitions

**Files:**

- Modify: `native/rdx-service/src/platform/macos.rs`
- Modify: `native/rdx-service/src/platform/macos/host.rs`
- Modify: `native/rdx-service/macos-native/src/lib.rs`
- Modify: `native/rdx-service/native/macos/rdx_iokit_disk.c`
- Modify: `src/renderer/views/compatibility-view.mjs`
- Modify: `src/renderer/localization/en.mjs`
- Modify: `src/renderer/localization/de.mjs`
- Test: `native/rdx-service/tests/macos_bridge.rs`
- Test: `test/compatibility-view.test.mjs`

**Interfaces:**

- Consumes: Task 2 capture lease and existing Disk Arbitration retained-media mapping.
- Produces: a truthful `busy` candidate when the volume remains mounted, cached pre-capture host facts for validation, explicit capture release/driver-rematch before host filesystem operations, and a visible macOS prerequisite.

- [ ] **Step 1: Write failing state-transition tests**

    Assert that mounted background discovery never unmounts, returns `busy`, and exposes the prerequisite; an explicitly unmounted candidate can enter a BOT management lease; host filesystem work first releases capture, proves the same USB serial after rematch, and revalidates the same capacity/media fingerprint before mutation.

- [ ] **Step 2: Verify RED**

    Run the focused Rust and Node view tests and confirm the new state assertions fail.

- [ ] **Step 3: Implement bounded transitions**

    Cache path-free host facts before capture, keep background discovery non-mutating, add an explicit native rematch wait bounded to 15 seconds, and fail closed on serial/topology/capacity drift or ambiguous matches. Do not retain raw mount paths across device capture.

- [ ] **Step 4: Expose the prerequisite in the UI**

    Explain that macOS 26 requires ejecting/unmounting the cartridge volume before opening a management session; preserve the distinction between unmounting the filesystem and physically ejecting the cartridge.

- [ ] **Step 5: Verify GREEN and commit**

    Run focused tests, `npm test`, and commit with `feat: add macOS RDX management sessions`.

### Task 4: Privileged service and physical acceptance

**Files:**

- Modify: `docs/verification/hardware-acceptance.md`
- Modify: `docs/verification/implementation-verification.md`
- Modify: `docs/verification/platform-verification.md`

**Interfaces:**

- Consumes: the packaged launchd socket contract and Tasks 1 through 3.
- Produces: exact host/device/firmware/cartridge evidence for discovery, status, Self, LED, write/read, safe eject, format, and failure recovery.

- [ ] **Step 1: Build the exact service artifact**

    Use Node 22.16.0 and a fresh `/tmp` Cargo target. Verify the artifact and helper metadata before any elevated execution.

- [ ] **Step 2: Run read-only physical discovery**

    Unmount `/dev/disk14` after revalidating USB serial `007820746632`, run elevated scan through the fixed service, and require a validated device with `TANDBERG`, `RDX`, revision `0227`, and a nonempty opaque `rdx:` ID.

- [ ] **Step 3: Run bounded diagnostics**

    Execute status refresh and Self, verify LED on/off with automatic off cleanup, and record exact terminal events. Do not claim visual LED proof without operator observation.

- [ ] **Step 4: Run media operations on the disposable cartridge**

    Perform the app-owned write/read file test and confirm cleanup, then safe eject and reinsert. Run format only after a fresh capacity/serial/topology confirmation and record filesystem rediscovery; stop on any identity drift or unknown completion.

- [ ] **Step 5: Update evidence documents**

    Record macOS version/build, app commit, dock USB serial, firmware `0227`, cartridge capacity, exact commands, timestamps, outcomes, cleanup, and which results were physically observed versus host-reported.

### Task 5: Full regression and delivery gate

**Files:**

- Inspect: all task diffs and generated `out/verification/darwin-arm64.json`

**Interfaces:**

- Consumes: all prior tasks.
- Produces: cross-platform software evidence plus honest macOS physical evidence.

- [ ] **Step 1: Run format checks**

    ```sh
    npm run format:check
    npm run native:check
    ```

- [ ] **Step 2: Run complete tests**

    ```sh
    npm test
    npm run native:quality
    npm run test:compact
    npm run test:visual
    env -u ELECTRON_RUN_AS_NODE npm run smoke
    ```

- [ ] **Step 3: Regenerate platform verification**

    Run `npm run verify:native-platform` with the connected device and inspect the JSON rather than inferring success from process exit.

- [ ] **Step 4: Inspect the focused diff**

    Run `git diff --check`, `git status --short`, and a scoped diff. Confirm no temporary probe, password, device path, raw USB identifier, or original-input modification remains.

- [ ] **Step 5: Commit the verified delivery**

    Stage only OpenRDXManager task files and use a focused Conventional Commit. Do not push, package, sign, or release without a separate user request.
