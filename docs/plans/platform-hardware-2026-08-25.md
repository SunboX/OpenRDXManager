<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Platform hardware implementation plan — 2026-08-25

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Connect the portable service core to real Windows, Linux, and macOS device/volume APIs while preserving explicit platform capability and hardware-verification states.

**Architecture:** Each OS implements the same `PlatformBackend` interface for discovery, SCSI execution, host volume operations, privilege readiness, and capability reporting. Unsafe/native boundaries are small, documented, and tested with pure conversion helpers before any real handle is opened.

**Technology:** Rust, Windows SetupAPI/SPTI, Linux udev/sysfs/SG_IO, macOS IOKit/Disk Arbitration/ServiceManagement bridge, native target tests

**Spec:** `docs/specs/full-implementation-2026-08-25.md`

## Constraints

- Never enumerate arbitrary storage as manageable RDX without validated identity/capability replies.
- Never accept an OS device path from Electron or CLI input; resolve it from the service-owned identity registry.
- Real handles use least privilege and close on every error path.
- Safe eject requires successful host flush/unmount before device/mechanical eject; force remains separate.
- Native build proof on each OS is required; cross-compilation does not replace native runtime proof.
- macOS must report a missing safe pass-through path instead of loading the obsolete vendor kext or weakening system security.

---

### Task 1: Define the platform backend and discovery registry

**Files:**

- Create: `native/rdx-service/src/platform/mod.rs`
- Create: `native/rdx-service/src/platform/registry.rs`
- Create: `native/rdx-service/tests/platform_registry.rs`
- Modify: `native/rdx-service/src/lib.rs`
- Modify: `native/rdx-service/src/service.rs`

**Interfaces:**

- Produces: `PlatformBackend`, `PlatformCapabilities`, `CandidateDevice`, `DeviceRegistry`, `ResolvedDevice`, and `discover_validated_devices`.
- Consumes: `Transport`, `HostOperations`, INQUIRY/status builders, and parsed identity.

- [ ] **Step 1: Write failing identity-pinning tests**

```rust
#[test]
fn stale_revision_and_path_reuse_are_rejected() {
    let mut registry = DeviceRegistry::new();
    registry.replace(vec![fixture_candidate("/dev/sg2", "SERIAL-A")]);
    let old = registry.snapshot("rdx:SERIAL-A").unwrap();
    registry.replace(vec![fixture_candidate("/dev/sg2", "SERIAL-B")]);
    assert_eq!(registry.resolve(&old.id, old.revision).unwrap_err().code(), "stale-device-revision");
}
```

- [ ] **Step 2: Run and observe missing registry failure**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test platform_registry`

Expected: FAIL.

- [ ] **Step 3: Implement registry revisions and candidate validation pipeline**

The registry owns paths/handles internally, creates opaque IDs from validated serial/product identity, invalidates authentication state on replacement/removal, and returns snapshots without platform paths.

- [ ] **Step 4: Run focused/full native tests**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test platform_registry && npm run native:test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/platform native/rdx-service/src/lib.rs native/rdx-service/src/service.rs native/rdx-service/tests/platform_registry.rs
git commit -m "feat: add native platform registry"
```

### Task 2: Implement the Windows backend

**Files:**

- Create: `native/rdx-service/src/platform/windows.rs`
- Create: `native/rdx-service/tests/windows_layout.rs`
- Create: `native/rdx-service/resources/windows/openrdx-hardware-service.xml`
- Modify: `native/rdx-service/Cargo.toml`

**Interfaces:**

- Produces: `WindowsBackend`, `build_scsi_pass_through(command)`, `parse_scsi_result(buffer)`, SetupAPI discovery, SPTI execution, volume mapping, privilege/service capability.
- Consumes: `PlatformBackend`, `Command`, and `TransportResult`.

- [ ] **Step 1: Write failing pure layout tests**

```rust
#[cfg(windows)]
#[test]
fn direct_pass_through_has_exact_cdb_direction_timeout_and_lengths() {
    let packet = build_scsi_pass_through(&log_sense(0x20)).unwrap();
    assert_eq!(&packet.spt.Cdb[..10], &[0x4D, 0, 0x20, 0, 0, 0, 0, 0, 0xFE, 0]);
    assert_eq!(packet.spt.DataIn, SCSI_IOCTL_DATA_IN);
    assert_eq!(packet.spt.DataTransferLength, 0xFE);
}
```

Add non-Windows serialization tests for Windows candidate normalization so the stable model remains testable on macOS/Linux.

- [ ] **Step 2: Run the native Windows test and observe missing backend failure**

Run on Windows: `cargo test --manifest-path native/rdx-service/Cargo.toml --test windows_layout`

Expected: FAIL.

- [ ] **Step 3: Implement SetupAPI candidate discovery and SPTI transport**

Use the `windows` crate with explicit Win32 feature flags. Open `\\.\PhysicalDriveN` with read/write sharing, choose direct pass-through for data and buffered pass-through for no-data commands, bound sense/data buffers, translate Win32 error separately from SCSI status, and close handles through RAII.

- [ ] **Step 4: Add service manifest and run native Windows checks**

Run on Windows:

```powershell
cargo fmt --manifest-path native/rdx-service/Cargo.toml -- --check
cargo clippy --manifest-path native/rdx-service/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path native/rdx-service/Cargo.toml
```

Expected: PASS without requiring an RDX device; service capability reports whether elevation/service installation is ready.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/platform/windows.rs native/rdx-service/tests/windows_layout.rs native/rdx-service/resources/windows native/rdx-service/Cargo.toml
git commit -m "feat: add Windows RDX transport"
```

### Task 3: Implement the Linux backend

**Files:**

- Create: `native/rdx-service/src/platform/linux.rs`
- Create: `native/rdx-service/tests/linux_sg_layout.rs`
- Create: `native/rdx-service/resources/linux/70-openrdx.rules`
- Create: `native/rdx-service/resources/linux/org.openrdx.hardware.policy`
- Modify: `native/rdx-service/Cargo.toml`

**Interfaces:**

- Produces: `LinuxBackend`, sysfs/udev discovery, `build_sg_io`, `parse_sg_io`, volume mapping, udev/polkit readiness.
- Consumes: `PlatformBackend`, `Command`, Linux `sg_io_hdr`.

- [ ] **Step 1: Write failing `SG_IO` layout/result tests**

```rust
#[cfg(target_os = "linux")]
#[test]
fn sg_io_maps_data_in_and_residual_bytes() {
    let owned = build_sg_io(&log_sense(0x21)).unwrap();
    assert_eq!(owned.header.dxfer_direction, SG_DXFER_FROM_DEV);
    assert_eq!(owned.header.cmd_len, 10);
    assert_eq!(owned.header.dxfer_len, 0xFE);
}
```

- [ ] **Step 2: Run on Linux and observe missing backend failure**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test linux_sg_layout`

Expected: FAIL.

- [ ] **Step 3: Implement `/sys/class/scsi_generic`/udev discovery and `SG_IO` execution**

Resolve block/volume parents without shell parsing, open `/dev/sg*` with explicit flags, pin CDB/data/sense buffers across ioctl, check host/driver/SCSI status and residuals, retry interrupted syscalls only, and map permission denial to `insufficient-permission`.

- [ ] **Step 4: Add least-privilege rules and run native Linux checks**

Run on Linux:

```sh
cargo fmt --manifest-path native/rdx-service/Cargo.toml -- --check
cargo clippy --manifest-path native/rdx-service/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path native/rdx-service/Cargo.toml
```

Expected: PASS without device access; rules are syntax-reviewed and capability output distinguishes missing installation.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/platform/linux.rs native/rdx-service/tests/linux_sg_layout.rs native/rdx-service/resources/linux native/rdx-service/Cargo.toml
git commit -m "feat: add Linux RDX transport"
```

### Task 4: Implement the macOS backend and safe capability probe

**Files:**

- Create: `native/rdx-service/src/platform/macos.rs`
- Create: `native/rdx-service/native/macos/rdx_iokit.h`
- Create: `native/rdx-service/native/macos/rdx_iokit.c`
- Create: `native/rdx-service/tests/macos_bridge.rs`
- Create: `native/rdx-service/resources/macos/com.openrdx.hardware.plist`
- Modify: `native/rdx-service/build.rs`
- Modify: `native/rdx-service/Cargo.toml`

**Interfaces:**

- Produces: `MacOsBackend`; C ABI `rdx_macos_enumerate`, `rdx_macos_execute_scsi`, `rdx_macos_unmount`, `rdx_macos_eject`, and `rdx_macos_free_result`.
- Consumes: IOKit SCSI task interfaces, Disk Arbitration, ServiceManagement readiness.

- [ ] **Step 1: Write failing bridge ownership/capability tests**

```rust
#[cfg(target_os = "macos")]
#[test]
fn bridge_reports_no_supported_user_client_without_claiming_success() {
    let result = MacOsBackend::new().probe_transport_for_service(known_non_scsi_service());
    assert_eq!(result.unwrap_err().code(), "transport-unavailable");
}
```

Add a C-level test that every allocated result is released exactly once by `rdx_macos_free_result`.

- [ ] **Step 2: Run on macOS and observe missing bridge failure**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test macos_bridge`

Expected: FAIL.

- [ ] **Step 3: Implement IOKit enumeration/task bridge and Disk Arbitration host operations**

The C bridge owns Core Foundation/IOKit references with one cleanup path, copies bounded CDB/data/sense fields into Rust-owned results, requires an exposed safe SCSI user client and exclusive access where documented, and returns a capability error when the current driver stack prevents safe pass-through. It must never attempt to load the vendor kext.

- [ ] **Step 4: Add ServiceManagement metadata and run native macOS checks**

Run on macOS:

```sh
cargo fmt --manifest-path native/rdx-service/Cargo.toml -- --check
cargo clippy --manifest-path native/rdx-service/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path native/rdx-service/Cargo.toml
```

Expected: PASS on Intel/Apple-silicon compile targets available locally; no-device runtime reports `ready` for discovery and a truthful raw-transport capability.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/platform/macos.rs native/rdx-service/native/macos native/rdx-service/tests/macos_bridge.rs native/rdx-service/resources/macos native/rdx-service/build.rs native/rdx-service/Cargo.toml
git commit -m "feat: add macOS RDX transport"
```

### Task 5: Add access-controlled privileged service endpoints

**Files:**

- Create: `native/rdx-service/src/endpoint.rs`
- Create: `native/rdx-service/tests/endpoint_access.rs`
- Create: `native/rdx-service/resources/linux/openrdx-hardware.service`
- Create: `native/rdx-service/resources/linux/openrdx-hardware.socket`
- Modify: `native/rdx-service/resources/windows/openrdx-hardware-service.xml`
- Modify: `native/rdx-service/resources/macos/com.openrdx.hardware.plist`
- Modify: `src/main/device-service-client.mjs`
- Modify: `test/device-service-client.test.mjs`

**Interfaces:**

- Produces: `ServiceEndpoint::development_stdio`, `PeerPolicy`, Windows named-pipe endpoint, Linux/macOS Unix-socket endpoint, peer authorization, protocol handshake, and endpoint readiness diagnostics.
- Consumes: the Phase 2 framed service protocol unchanged across transports.

- [ ] **Step 1: Write failing endpoint/peer authorization tests**

```rust
#[test]
fn endpoint_rejects_a_peer_outside_the_configured_application_identity() {
    let policy = PeerPolicy::for_fixture_user(501, "com.openrdx.manager");
    let peer = FixturePeer::new(502, "untrusted.client");
    assert_eq!(policy.authorize(&peer).unwrap_err().code(), "unauthorized-service-peer");
}
```

Add a Node test proving production mode never silently falls back from a missing privileged endpoint to an unprivileged child for mutating operations.

- [ ] **Step 2: Run and observe missing endpoint failure**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test endpoint_access && npm test -- test/device-service-client.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement development stdio and access-controlled production endpoints**

On Windows use a local named pipe with an explicit current-user/administrators ACL. On Linux use a root-owned systemd Unix socket with the packaged group/polkit policy. On macOS use a ServiceManagement-registered launch daemon with a root-owned Unix socket and peer credential/code-identity validation supplied by the native bridge. The Electron client chooses the platform endpoint in production and uses stdio only for development/tests.

- [ ] **Step 4: Run native endpoint and Electron supervision tests on each OS**

Run: `npm run native:test && npm test -- test/device-service-client.test.mjs`

Expected: PASS; missing registration reports `insufficient-permission` or `service-not-installed` and never reports hardware readiness.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/endpoint.rs native/rdx-service/tests/endpoint_access.rs native/rdx-service/resources src/main/device-service-client.mjs test/device-service-client.test.mjs
git commit -m "feat: secure native service endpoints"
```

### Task 6: Add safe host volume, eject, format, and drive-letter operations

**Files:**

- Create: `native/rdx-service/src/operations/volume.rs`
- Create: `native/rdx-service/src/operations/eject.rs`
- Create: `native/rdx-service/src/operations/drive_letter.rs`
- Create: `native/rdx-service/tests/host_operation_state.rs`
- Modify: all three platform backend modules

**Interfaces:**

- Produces: `run_write_read_test`, `safe_eject`, `force_eject`, `partition_and_format`, `set_drive_letter`, and `reset_drive_letter`.
- Consumes: service-owned `ResolvedDevice`, `HostOperations`, selected filesystem enum, and exact confirmation token.

- [ ] **Step 1: Write failing host-operation tests**

```rust
#[test]
fn format_never_starts_layout_change_when_unmount_fails() {
    let mut host = FixtureHost::with_unmount_error();
    let result = partition_and_format(&mut host, disposable_media(), FileSystem::ExFat, valid_confirmation());
    assert_eq!(result.unwrap_err().stage(), "unmount");
    assert_eq!(host.layout_change_count(), 0);
}

#[test]
fn safe_eject_never_falls_back_to_force() {
    let mut host = FixtureHost::with_busy_volume();
    assert_eq!(safe_eject(&mut host, ready_device()).unwrap_err().code(), "volume-busy");
    assert_eq!(host.force_count(), 0);
}
```

- [ ] **Step 2: Run and observe missing operation failures**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test host_operation_state`

Expected: FAIL.

- [ ] **Step 3: Implement staged host operations per platform**

Write/Read uses a random app-owned filename and exact compare/delete cleanup. Format checks host filesystem tooling before unmount, performs supported layout/format, ensures a non-zero MBR signature when applicable, and requires rediscovery. Windows drive letter changes only the selected serial mapping. Safe/force eject remain distinct functions.

- [ ] **Step 4: Run native target and fixture tests**

Run: `npm run native:test` on each supported host.

Expected: PASS; host dependency absence is `host-dependency-missing` before mutation.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/operations native/rdx-service/src/platform native/rdx-service/tests/host_operation_state.rs
git commit -m "feat: add cross-platform RDX volume operations"
```

### Task 7: Connect real discovery/status to Electron

**Files:**

- Modify: `native/rdx-service/src/service.rs`
- Modify: `src/main/device-service-client.mjs`
- Modify: `src/renderer/app-controller.mjs`
- Create: `test/device-discovery-flow.test.mjs`
- Modify: `test/renderer-dom.test.mjs`

**Interfaces:**

- Produces: one-second non-overlapping auto-scan, manual scan debounce, service/device state events, candidate rejection diagnostics, and full status snapshots.

- [ ] **Step 1: Write failing scan/state tests**

```js
test('auto scan never overlaps a slow native scan', async () => {
    const service = createDeferredScanService()
    const controller = createDeviceController({ service, intervalMs: 1_000 })
    controller.startAutoScan()
    await advanceClock(3_100)
    assert.equal(service.maxConcurrentScans, 1)
})
```

- [ ] **Step 2: Run and observe missing controller behavior**

Run: `npm test -- test/device-discovery-flow.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement scan scheduling, selection stability, field updates, and no-media behavior**

Preserve a selected device by opaque ID across refreshes, clear it on removal, invalidate stale authentication sessions, and render every documented status field/unavailable reason.

- [ ] **Step 4: Run integrated no-device/fixture verification**

```sh
npm run native:test
npm test
env -u ELECTRON_RUN_AS_NODE npm run smoke
```

Expected: PASS with an honest empty list on the current machine.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/service.rs src/main/device-service-client.mjs src/renderer test/device-discovery-flow.test.mjs test/renderer-dom.test.mjs
git commit -m "feat: connect live RDX discovery"
```

### Task 8: Record native platform verification without overstating hardware proof

**Files:**

- Create: `scripts/verify-native-platform.mjs`
- Create: `docs/verification/platform-verification.md`
- Modify: `package.json`
- Modify: `README.md`
- Create: `test/platform-verification.test.mjs`

**Interfaces:**

- Produces: machine-readable platform report with OS/arch, tool versions, build/test results, service handshake, discovered-device count, and `hardwareVerified: false` until explicit acceptance evidence exists.

- [ ] **Step 1: Write failing report-schema test**

```js
test('platform report separates native runtime from hardware proof', async () => {
    const report = await readFixtureReport()
    assert.equal(report.nativeService.smokePassed, true)
    assert.equal(report.hardware.verified, false)
    assert.deepEqual(report.hardware.operations, [])
})
```

- [ ] **Step 2: Run and observe missing report failure**

Run: `npm test -- test/platform-verification.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement bounded verification script and documentation template**

The script runs checks but never mutates a device. It writes under `out/verification/`, which remains generated/untracked, and documentation records only reviewed outputs.

- [ ] **Step 4: Run on each native OS and review reports**

Run: `npm run verify:native-platform`

Expected: exit `0` when build/tests/handshake pass; a missing device is reported, not failed or marked verified.

- [ ] **Step 5: Commit**

```sh
git add scripts/verify-native-platform.mjs docs/verification/platform-verification.md package.json package-lock.json README.md test/platform-verification.test.mjs
git commit -m "test: document native platform readiness"
```
