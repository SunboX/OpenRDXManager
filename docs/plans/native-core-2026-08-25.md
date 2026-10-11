<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Native service core implementation plan — 2026-08-25

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Build the portable Rust protocol, parsing, operation, service, and CLI core without requiring physical RDX hardware.

**Architecture:** One Rust package exposes a library plus `openrdx-hardware` and `rdxctl` binaries. Exact protocol logic is platform-neutral and runs against a deterministic transport trait; OS adapters arrive in Phase 3.

**Technology:** Rust 2024 edition, serde, serde_json, thiserror, zeroize, sha2, hmac, pbkdf2, tempfile, cargo test

**Spec:** `docs/specs/full-implementation-2026-08-25.md`

## Constraints

- Every public Rust item has `///` documentation and every unsafe block states its invariant.
- No public service request accepts raw CDB bytes or an OS device path.
- Parsers reject short, oversized, inconsistent, and malformed payloads without panicking.
- Password-derived material uses zeroizing buffers and never implements `Debug` with content.
- Only protocol facts proven in docs/analysis receive an `Enabled` evidence status.
- Hardware absence is a successful service state with an empty device list, not hardware proof.

---

### Task 1: Scaffold the Rust package and portable model

**Files:**

- Create: `native/rdx-service/Cargo.toml`
- Create: `native/rdx-service/src/lib.rs`
- Create: `native/rdx-service/src/model.rs`
- Create: `native/rdx-service/src/error.rs`
- Create: `native/rdx-service/tests/model_contract.rs`
- Modify: `package.json`

**Interfaces:**

- Produces: `DeviceIdentity`, `DeviceSnapshot`, `Capability`, `CapabilityState`, `OperationRequest`, `OperationEvent`, `RdxError`, and npm scripts `native:test`, `native:fmt`, `native:check`.

- [ ] **Step 1: Write the failing Rust model test**

```rust
#[test]
fn operation_request_does_not_deserialize_an_os_path() {
    let json = r#"{"kind":"SelfTest","device_id":"rdx:1","device_revision":2,"os_path":"/dev/sg4"}"#;
    assert!(serde_json::from_str::<OperationRequest>(json).is_err());
}
```

- [ ] **Step 2: Run and observe the missing-manifest failure**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml`

Expected: FAIL because the package does not exist.

- [ ] **Step 3: Create the package, strict serde models, errors, and npm scripts**

Use `#[serde(deny_unknown_fields)]`, kebab-case external reason codes, opaque device IDs, monotonic discovery revisions, and structured errors with `code`, `stage`, `retryable`, and optional sanitized sense summary.

- [ ] **Step 4: Run Rust and Node contract tests**

Run: `npm run native:test && npm test -- test/contracts.test.mjs`

Expected: PASS with matching external enum strings.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service package.json package-lock.json
git commit -m "feat: add native RDX service model"
```

### Task 2: Implement exact command builders and endian helpers

**Files:**

- Create: `native/rdx-service/src/protocol/mod.rs`
- Create: `native/rdx-service/src/protocol/cdb.rs`
- Create: `native/rdx-service/src/protocol/endian.rs`
- Create: `native/rdx-service/tests/cdb_golden.rs`

**Interfaces:**

- Produces: `Command`, `DataDirection`, `self_test()`, `led_test(on)`, `unit_reset()`, `log_sense(page)`, `mode_sense(page)`, `mode_select(payload, save_pages)`, `security_in(selector)`, `security_out(selector, payload)`, and `write_buffer(mode, offset, bytes)`.

- [ ] **Step 1: Write failing exact-byte tests**

```rust
#[test]
fn exact_led_and_firmware_boundaries_match_reference_commands() {
    assert_eq!(led_test(true).cdb, [0x1D, 0, 0, 0, 8, 0]);
    assert_eq!(led_test(true).data_out(), &[0x80, 0, 0, 4, 0, 0, 0, 0]);
    assert_eq!(write_buffer(0x04, 0, &[0; 0x1000]).cdb,
               [0x3B, 0x04, 0, 0, 0, 0, 0, 0x10, 0, 0]);
    assert_eq!(write_buffer(0x05, 0xF29E, &[]).cdb,
               [0x3B, 0x05, 0, 0, 0xF2, 0x9E, 0, 0, 0, 0]);
}
```

- [ ] **Step 2: Run and confirm missing builder failures**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test cdb_golden`

Expected: FAIL.

- [ ] **Step 3: Implement bounded builders from the exact documented layouts**

Reject offsets/lengths exceeding 24 bits, payload/CDB length mismatches, invalid mode pages, and unsupported selectors. Preserve data direction and timeout in `Command` rather than encoding host policy into CDB bytes.

- [ ] **Step 4: Run focused/full Rust tests**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test cdb_golden && npm run native:test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/protocol native/rdx-service/tests/cdb_golden.rs
git commit -m "feat: build exact RDX commands"
```

### Task 3: Add bounded status, mode, descriptor, and sense parsers

**Files:**

- Create: `native/rdx-service/src/protocol/log_sense.rs`
- Create: `native/rdx-service/src/protocol/mode_page.rs`
- Create: `native/rdx-service/src/protocol/security.rs`
- Create: `native/rdx-service/src/protocol/sense.rs`
- Create: `native/rdx-service/tests/parser_fixtures.rs`

**Interfaces:**

- Produces: `parse_log_page`, `RdxFeaturePage`, `SecurityDescriptor`, `SecurityEvidence`, and `SenseData::parse`.

- [ ] **Step 1: Write failing bounded-parser tests**

```rust
#[test]
fn rejects_short_log_parameter_and_unknown_security_write_mapping() {
    assert!(parse_log_page(&[0x20, 0, 0, 7, 0, 1, 0, 4, 0xAA]).is_err());
    assert_eq!(SecurityEvidence::for_operation(SecurityOperation::CreateCredential),
               SecurityEvidence::Incomplete);
}

#[test]
fn parses_signature_failure_sense() {
    let sense = SenseData::parse(&[0x70, 0, 0x07, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x74, 0x08]).unwrap();
    assert_eq!(sense.code(), "firmware-signature-error");
}
```

- [ ] **Step 2: Run and observe missing-parser failures**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test parser_fixtures`

Expected: FAIL.

- [ ] **Step 3: Implement length-first parsers and evidence registry**

Parse big-endian LOG parameter headers, preserve unknown parameter IDs as bounded opaque metadata, preserve unrelated MODE page bytes for round trips, accept only descriptor IDs/lengths proven by evidence, and map sense without discarding raw key/ASC/ASCQ.

- [ ] **Step 4: Run parser/full tests**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test parser_fixtures && npm run native:test`

Expected: PASS and no parser panic under malformed fixtures.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/protocol native/rdx-service/tests/parser_fixtures.rs
git commit -m "feat: parse RDX protocol responses"
```

### Task 4: Validate and chunk modern firmware images

**Files:**

- Create: `native/rdx-service/src/firmware.rs`
- Create: `native/rdx-service/tests/firmware_0283.rs`
- Reference only: `original-inputs/RDX2E__STD__F-0283.bin`
- Reference only: `docs/protocols/firmware-update.md`

**Interfaces:**

- Produces: `FirmwareImage::load(path, expected_product)`, `FirmwareImage::chunks()`, `FirmwareChunk`, and `finalize_command()`.

- [ ] **Step 1: Write failing tests against immutable firmware evidence**

```rust
#[test]
fn firmware_0283_has_sixteen_chunks_and_exact_tail() {
    let image = FirmwareImage::load(fixture_path("RDX2E__STD__F-0283.bin"), ProductFamily::Usb3Sata3).unwrap();
    let chunks = image.chunks().collect::<Vec<_>>();
    assert_eq!(image.len(), 62_110);
    assert_eq!(chunks.len(), 16);
    assert_eq!((chunks[15].offset, chunks[15].bytes.len()), (0xF000, 0x029E));
    assert_eq!(image.finalize_command().cdb[3..6], [0x00, 0xF2, 0x9E]);
}
```

- [ ] **Step 2: Run and observe missing firmware API**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test firmware_0283`

Expected: FAIL.

- [ ] **Step 3: Implement immutable loading, structural/product checks, and 4 KiB chunking**

Do not copy or modify the source evidence. Reject wrong extension/family, wrong length/header/checks, oversized files, and signed downgrade violations before returning chunks.

- [ ] **Step 4: Run focused/full tests**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test firmware_0283 && npm run native:test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/firmware.rs native/rdx-service/tests/firmware_0283.rs
git commit -m "feat: validate RDX firmware images"
```

### Task 5: Implement transport traits and deterministic operations

**Files:**

- Create: `native/rdx-service/src/transport.rs`
- Create: `native/rdx-service/src/host.rs`
- Create: `native/rdx-service/src/operations/mod.rs`
- Create: `native/rdx-service/src/operations/diagnostics.rs`
- Create: `native/rdx-service/src/operations/firmware.rs`
- Create: `native/rdx-service/src/operations/modes.rs`
- Create: `native/rdx-service/tests/operation_state.rs`

**Interfaces:**

- Produces: `Transport::execute`, `HostOperations`, `OperationContext`, `run_self_test`, `run_led_test`, `run_firmware_update`, `set_drive_mode`, and `set_sata_mode`.

- [ ] **Step 1: Write failing state-machine tests**

```rust
#[test]
fn firmware_retries_once_from_zero_then_waits_for_reconnect() {
    let mut transport = FixtureTransport::fail_once_at_offset(0x3000);
    let events = run_firmware_update(&mut transport, &mut fixture_host(), fixture_image()).unwrap();
    assert_eq!(transport.offsets().iter().filter(|&&v| v == 0).count(), 2);
    assert!(events.iter().any(|event| event.stage == "reconnect"));
}

#[test]
fn led_failure_still_attempts_led_off_cleanup() {
    let mut transport = FixtureTransport::fail_on_call(2);
    assert!(run_led_test(&mut transport, &mut fixture_host()).is_err());
    assert!(transport.commands().iter().any(|command| command.data_out() == [0x80, 0, 0, 4, 0, 0, 0, 1]));
}
```

- [ ] **Step 2: Run and confirm operation functions are missing**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test operation_state`

Expected: FAIL.

- [ ] **Step 3: Implement fixture transport, host trait, staged operations, and documented retry/cleanup rules**

Every progress event contains operation ID, stage, fraction, message key, and cancellation state. Mode setters must MODE SENSE first, preserve bytes, skip a no-op selection, write, reset/reconnect where required, and verify readback.

- [ ] **Step 4: Run focused/full tests**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test operation_state && npm run native:test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/transport.rs native/rdx-service/src/host.rs native/rdx-service/src/operations native/rdx-service/tests/operation_state.rs
git commit -m "feat: orchestrate RDX device operations"
```

### Task 6: Implement framed service protocol and no-device binary

**Files:**

- Create: `native/rdx-service/src/service.rs`
- Create: `native/rdx-service/src/bin/openrdx-hardware.rs`
- Create: `native/rdx-service/tests/service_protocol.rs`
- Modify: `src/main/device-service-client.mjs`
- Modify: `test/device-service-client.test.mjs`

**Interfaces:**

- Produces: protocol-version handshake, `list-devices`, `scan`, `start-operation`, `cancel-operation`, progress/result events, and clean shutdown.
- Consumes: high-level `OperationRequest` only.

- [ ] **Step 1: Write failing cross-language handshake tests**

```js
test('native service handshakes and reports an honest empty device list', async () => {
    const client = await DeviceServiceClient.start({ executable: nativeTestBinary })
    assert.equal(client.protocolVersion, 1)
    assert.deepEqual(await client.listDevices(), [])
    assert.equal(client.capabilities.hardwareVerified, false)
})
```

Add Rust tests rejecting frames over the maximum length, wrong protocol versions, unknown fields, and concurrent operations.

- [ ] **Step 2: Run Node/Rust tests and observe missing binary/protocol failures**

Run: `npm run native:test && npm test -- test/device-service-client.test.mjs`

Expected: FAIL.

- [ ] **Step 3: Implement length-framed stdin/stdout service and connect Electron client**

Use stderr for sanitized diagnostics only. Flush every response/event, bound frame size, close cleanly on EOF, and map crashes to `service-unavailable` without retry loops during an active operation.

- [ ] **Step 4: Run cross-language tests**

Run: `npm run native:test && npm test -- test/device-service-client.test.mjs && npm test`

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/service.rs native/rdx-service/src/bin/openrdx-hardware.rs native/rdx-service/tests/service_protocol.rs src/main/device-service-client.mjs test/device-service-client.test.mjs
git commit -m "feat: connect native hardware service"
```

### Task 7: Add the command-line interface and full native quality gate

**Files:**

- Create: `native/rdx-service/src/bin/rdxctl.rs`
- Create: `native/rdx-service/tests/cli.rs`
- Modify: `package.json`
- Modify: `README.md`

**Interfaces:**

- Produces: `rdxctl --help`, `--version`, `--scan`, `--eject <target>`, and `--force` with stable exit codes.

- [ ] **Step 1: Write failing CLI tests**

```rust
#[test]
fn force_without_eject_is_rejected_without_device_access() {
    let output = Command::new(rdxctl()).arg("--force").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--force requires --eject"));
}
```

- [ ] **Step 2: Run and observe missing binary failure**

Run: `cargo test --manifest-path native/rdx-service/Cargo.toml --test cli`

Expected: FAIL.

- [ ] **Step 3: Implement strict argument parsing, stable output, and npm commands**

Define exit `0` success, `2` usage, `3` service/host transport, `4` device/SCSI failure, `5` prerequisite/capability rejection, and `6` partial/ambiguous operation. `--force` changes host eject policy only and always emits the cache-risk warning.

- [ ] **Step 4: Run full quality gate**

```sh
cargo fmt --manifest-path native/rdx-service/Cargo.toml -- --check
cargo clippy --manifest-path native/rdx-service/Cargo.toml --all-targets -- -D warnings
npm run native:test
npm test
```

Expected: PASS with no warnings.

- [ ] **Step 5: Commit**

```sh
git add native/rdx-service/src/bin/rdxctl.rs native/rdx-service/tests/cli.rs package.json package-lock.json README.md
git commit -m "feat: add RDX command line control"
```
