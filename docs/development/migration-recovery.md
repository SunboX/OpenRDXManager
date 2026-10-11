<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Migration recovery implementation

This maintainer checkpoint describes recovery of a previously prepared macOS
migration. The Manager route permits selecting a currently connected bootloader
on any USB port. A physical recovery through Manager completed on macOS on
2026-09-11 without J7, using the original port. Different-port selection remains
covered by software/native-boundary tests rather than a separate live attempt.
See the [physical result](../evidence/firmware-first-installation-20260911/physical-recovery.md).

## Manager workflow

Choose the saved dock by its serial number, select the connected bootloader,
and confirm that it is the physical dock associated with that saved record.
The dock may use a different port from its original installation. Keep it on
the selected port throughout this recovery attempt, including the requested
power cycle, and explicitly continue after completing that step.

The TI bootloader exposes a generic identity rather than the saved dock's unit
serial. Its appearance alone cannot associate it with a saved record. The
operator must make that physical association before starting recovery.

Saved records remain available after a completed recovery. If the same dock
later returns to the bootloader, the operator can explicitly select its
original record again. A missing record or one that fails validation cannot
be used to recover a dock. Listing records never creates replacement data.

## Saved evidence and ownership

`PreparedMigration::begin_recovery_existing` cold-validates the original
schema-one receipt and its six artifacts, then creates an independent private
recovery copy. The original files and original journal remain unchanged. The
copy contains all six original artifact files byte-for-byte. A schema-two
receipt records the original bundle identifier and its receipt digest, and a
separate durable journal begins with `Prepared` and `RecoveryResumed`. Recovery
copies cannot themselves become origins; subsequent attempts select the same
immutable schema-one original.

The original captured serial, location, manufacturing records and operational
state are never rewritten to accommodate a new USB port. The selected port and
current enumeration epoch belong only to the new attempt. The native controller
revalidates that observed route before opening it and requires it throughout
bootstrap return, power-cycle acknowledgment and final verification. Bus numbers
and location IDs are neither guessed nor converted into another route.

`migration::recovery_inventory()` performs read-only validation before exposing
an original bundle's identifier, unit serial, fixed source/target versions and
saved state. It checks private ownership/modes, bounded files and inventory,
the canonical receipt/journal chain, all artifacts, release/template pins and
flat copy provenance. Valid copies update their original's latest saved state
by generated creation identifier; they are not separate selectable originals.
A recorded completion describes saved evidence, not the dock's current state,
and does not remove the original from explicit selection.

A missing fixed recovery directory produces an empty inventory without creating
it. Recognized corrupt or incomplete bundles yield a fixed unavailable reason
without disclosing their unvalidated serial or record fields; other valid
originals remain available. Unsafe ancestry, unexpected root entries and excess
inventory fail the listing with a fixed diagnostic. The service maps available
entries to the closed UI fields `bundleId`, `serial`, `sourceVersion`,
`targetVersion` and `recoveryNeeded`. Neither raw records, private hashes nor
filesystem paths cross this boundary.

The personalized bootstrap comes directly from the reopened prepared bundle.
The final image is pinned to the unmodified public OpenRDX 1.07 container
SHA-256 `1e26a407d5178f1344682798b7ab935f407fe2ce160fb3d03354cf823a951a9e`.
The ordinary production firmware validator also checks the exact published boot
digest, container format and OpenRDX integrity block. Neither a bare template
nor caller-supplied image bytes can be programmed through these recovery routes.

## Ordered attempt

1. Require explicit association of the saved unit with the freshly selected
   TI ROM route. Retain the global native hardware owner, revalidate the
   selected location/epoch, open its exact HID and bulk interfaces and require
   the exact identification feature.
2. Durably journal setup intent, send the documented setup report once, and
   journal accepted completion. Setup is erase-capable.
3. Durably journal transfer intent, transfer the saved personalized bootstrap
   once, and require complete native transport acceptance before journaling
   transfer completion.
4. Durably journal reset intent, send the documented reset report once, and
   journal accepted completion. No reset is sent after an incomplete transfer.
5. Release the ROM owners, observe the application epoch, and publish the new
   power-cycle prompt. The operator must disconnect/reconnect at the selected
   attempt port with J7 open and explicitly acknowledge that step. Merely
   observing enumeration cannot satisfy this gate. If an application was already present before the prompt, its
   unchanged registry epoch is insufficient. If no application exists before
   the prompt, the fresh reply is an operator attestation: enumeration cannot
   independently distinguish physical cycling from delayed automatic boot.
   Waiting for an application before prompting would incorrectly block devices
   that require the documented physical cycle to leave ROM.
6. Observe the exact source serial, selected attempt location and application PID
   `1A5A:0005`, then retain the fresh native discovery lease. On that same lease,
   require firmware revision `0107`, USB3/SATA3 family, an empty bay and complete
   raw-record equality before permitting any final-image transfer.
7. Journal final-transfer intent and send the ordinary mode-04 chunks exactly
   once. After every chunk succeeds, journal transfer completion and a separate
   activation intent, then send mode-05 once. Only a fully accepted mode-05
   permits final verification; no failed chunk reaches the finalizer.
8. Require a new exact-target application registry epoch after mode-05, acquire
   a fresh retained lease, and recheck revision, empty bay and raw records.
   Only then append `FinalUpdateVerified` and return completed-release status.

Every failed or uncertain operation stops dependent work and attempts a durable
`RecoveryRequired` append. While a resolved application lease exists, failure is
journaled before releasing it, including a caught panic. The controller never
automatically retries a write or sends explicit reset/finalization as failure
cleanup. macOS can reset/rematch the device when a captured USB owner is released;
process exit therefore cannot promise a reset-free boundary. An intent without a corresponding
completion event remains ambiguous; reconnecting alone cannot resolve it.

The three raw reads are existing six-byte, LUN-0 BOT commands:

| Record                    | CDB                 | Exact returned bytes |
| ------------------------- | ------------------- | -------------------- |
| Manufacturing first half  | `E7 00 03 E0 00 80` | 128                  |
| Manufacturing second half | `E7 00 03 E0 80 80` | 128                  |
| Operational state         | `E7 00 03 F0 00 40` | 64                   |

Their actual-byte dispatcher proof is recorded in
[FLASH_READ_EVIDENCE.md](../../analysis/migration-bootstrap/FLASH_READ_EVIDENCE.md).
Record verification proves that the saved semantic reconstruction is present;
it does not claim the original capture exposed every byte of the vendor flash.
Native report completion is transport acceptance, not flash readback. Firmware
revision and records also do not constitute an independent full executable
flash hash; the completed-release result additionally depends on the exact
validated transfer, accepted mode-05 and subsequent target re-enumeration.

`PreparedMigration::verify_records_at_location(readback, selected_location)`
uses the nonzero attempt location only for physical binding. It preserves the
strict saved serial, vendor, receiver identity and complete manufacturing/state
comparisons, including checksums. The original `verify_records` method remains
strictly bound to the captured location.

`service::recovery::verify_existing_records(bundle_id)` is a separate read-only
API. It acquires the same owner and fresh exact-target lease, performs discovery
and fixed record reads, and neither changes the journal nor claims final-release
installation.

## Maintainer entry points

The Manager uses explicit original-bundle selection and a fresh ROM target token
through the native service. The token identifies a current port/epoch, not a unit
serial. Service admission retains the existing global hardware owner and the
exclusive operation lock through the attempt; inventory alone authorizes no
operation.

The legacy `openrdx-hardware --recover-migration <bundle-id>` CLI remains bound
to the originally captured port. It accepts no image, serial, path, port or
command override and requires an interactive terminal. Its gate discards pending
terminal input with Darwin `tcflush(stdin, TCIFLUSH)` before arming, then requires
the literal `POWER CYCLED` followed by Return. EOF, pipes, malformed input and
failed flushing cannot acknowledge the step. This maintainer distinction does
not change the Manager's selection workflow.

## Validation checkpoint

The controller tests cover sequence ordering, each operation failure boundary,
durable intent failures, every chunk/finalizer failure, normal final CDBs,
operator/USB gating, invalid identifiers and progress-channel failures. CLI tests
cover argument rejection, terminal requirement, exact acknowledgment and fixed
sanitized results. They use fake boundaries and synthetic image fixtures.

Earlier native suites and 255 service tests passed before the Manager any-port
integration. That earlier checkpoint does not cover the new service admission,
inventory, UI selection and selected-port integration. The current 51 focused
migration tests pass, including the safe inventory, selected-port record checks,
cold loading and immutable-copy provenance. The updated complete native suite
passed 565 tests, and the final recovery controller/session subset passed 25.
Current JavaScript checks, two remaining full-suite test failures, Electron
startup, and the completed physical recovery are recorded in the linked
checkpoint. Run from the Manager directory:

```sh
cargo test --manifest-path native/rdx-service/Cargo.toml service::recovery --lib
cargo test --manifest-path native/rdx-service/Cargo.toml --bin openrdx-hardware recovery_cli
cargo test --manifest-path native/rdx-service/Cargo.toml migration --lib
cargo check --manifest-path native/rdx-service/Cargo.toml --bin openrdx-hardware
npm run format:check
```

The relevant implementation is in `src/service/recovery.rs` and its native/test
modules, `src/service/recovery_session.rs`, and `src/migration/recovery.rs`,
`storage/inventory.rs` and `readback.rs`, under `native/rdx-service`. The legacy
CLI remains in `src/bin/openrdx-hardware/recovery_cli.rs`. The ordinary updater's
retry and failure-cleanup routines are deliberately not called by this recovery
controller; only its validated image and command builders are shared.
