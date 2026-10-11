<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Manufacturing backup and restore protocol

Use the [operator guide](../manufacturing-backup-restore.md) for backup and restore steps. This reference includes the initial macOS storage design and subsequent preservation checks; current platform availability is reported by the live service.

The Utilities workspace provides **Backup manufacturing data** and an explicit
**Restore manufacturing data** action. Backups are stored privately by the macOS
hardware service and listed by creation time and original unit serial, with 128 records per history page. A backup
contains the complete 256-byte manufacturing record at SPI address `0x3E000`.
Manual backups and the mandatory backup before restoration also contain all
4096 bytes of its erase sector, including the neighboring 3840 bytes.

Each firmware update must save and independently verify a durable backup before
its first write. This includes installing a vendor image through an OpenRDX
receiver. If capturing complete stable bytes or saving the backup fails, the update stops.
Every attempt creates a new backup and never overwrites an earlier one. The
first vendor-2.83-to-OpenRDX installation retains its separately verified migration
bundle, containing the original exposed factory responses; this is a semantic
factory-data backup, not a raw flash capture. See the migration documentation for
the unexposed fields that cannot be recovered from those vendor responses.

## Restoring an original record

The [restore guide](../manufacturing-backup-restore.md#restore-an-original-record) describes dock selection, original-serial confirmation, readback and the required power cycle.

The restore capability is probed on the actual receiver. Existing firmware that
only supports serial repair cannot restore the entire record. The new matching
firmware receiver must be installed before the Restore action becomes available.
No version string alone enables the operation. Building the code does not install
that firmware, and the Manager does not automatically reset the dock after restore.

A checksum-valid current record normally requires a backup belonging to the same
service device identity and unit serial. A previously reconstructed record can
have a valid checksum and still contain a replacement serial. Recovering the
original identity requires a separate explicit identity-change confirmation,
in addition to the typed original serial and physical dock association. That
confirmation is cleared when the target, revision, or selected backup changes.
If the current record is erased or corrupt, its fallback identity may also differ.
Erased
and corrupt backups remain available as evidence but cannot be restoration
sources. A valid saved record without a decimal unit serial cannot be selected
for restore. Restoration changes the complete original record, including opaque
factory fields; it does not synthesize factory data.

The receiver independently checks its physical cartridge sensor and idle
mechanism, compares the expected current 256 bytes and a CRC-32 of the whole
sector, and preserves the neighboring bytes. Both the receiver and host verify
the result. No failed or uncertain restore is automatically retried. A lost reply
keeps the Manager's operation lock until an ordered inventory refresh can
reconcile native ownership. An interrupted sector erase/write still requires
recovery; the operation is not power-fail atomic, and the durable pre-restore
`sector.bin` preserves the original neighboring bytes for that assessment.

## Backup storage and update checks

On macOS, backups live below
`~/Library/Application Support/OpenRDXManager/manufacturing-backups/record-*`.
Manual backups, automatic backups before firmware updates and restores, and
restore selection all use this single location. **Open backup folder** opens
that directory in the system file manager. Each unique desktop-user-owned directory contains `manufacturing.bin` and `manifest.json`;
complete-sector snapshots also include `sector.bin`. The manifest records the
opaque original device identifier, fixed address, lengths and SHA-256 integrity
checks. Directories use mode `0700`, files use `0600`, and descriptor-relative
operations reject symlinks, unexpected ownership, unsafe permissions and hard
links. Data and directory entries are synced, then reopened and compared before
hardware mutation. Raw bytes and paths never cross the renderer interface.

Existing records from the former root-only `/private/var/db/OpenRDXManager/manufacturing-backups`
folder are moved into this store before backup, inventory, restore selection, or
folder opening. There is no legacy read fallback or second active backup folder.
Relocation resumes after interruption, preserves incomplete records as evidence,
and removes each source only after the destination is durable. Same-filesystem
moves preserve the original files; cross-filesystem moves verify every source
artifact before removing it. Conflicting contents stop relocation without
replacing either record. The authenticated desktop identity supplies the owner;
no renderer request can select a destination, and missing identity fails closed.

Ordinary OpenRDX updates read two fixed 128-byte `E7` ranges. Full identity checks
bracket the read on the same retained device lease. The record is classified using the four independent byte-lane checksum sums
(initial lanes `78 56 34 12`) and an entirely erased check, but preservation
covers every raw byte even when the record is corrupt. A stable corrupt record is also preserved byte for byte so the dock can
install a receiver capable of restoring its saved factory data. This does not
repair the record or claim its checksum is valid. A complete erased baseline allows installing
a receiver capable of recovery without silently reconstructing lost factory data.

The saved baseline is compared again after storage, before whole-image retry,
before finalization, and after activation on supported OpenRDX firmware. Vendor
firmware has no established postboot raw-record read command, so a verified
pre-update backup and pre-finalizer equality are required, but postboot raw-record
preservation is not claimed for vendor firmware.

The initial Windows and Linux implementations rejected updates without durable
backup storage. This was a historical prerequisite boundary; later platform
implementations must still satisfy private persistence and independent readback.
Use the live service capability and verification records for current support.

## Source contracts and verification

- `src/service/hardware/manufacturing.rs` owns native admission, original-serial
  association, pre-restore persistence and one-shot dispatch.
- `src/platform/registry/migration.rs` retains the same device lease for complete
  sector capture, physical-bay checks, compare-and-set and readback.
- `src/migration/storage/manufacturing.rs` owns immutable private storage and
  independently validated inventory, including older 256-byte automatic backups.
- `src/protocol/manufacturing.rs`, `macos-native/src/manufacturing_contract.rs`
  and `native/macos/rdx_manufacturing_contract.inc` validate the fixed restore
  request independently. These paths are relative to `native/rdx-service/`.
- The matching firmware receiver is implemented in the sibling firmware project.

Deterministic tests exercise real filesystem persistence, service/registry
ownership, simulated SCSI transport, invalid and changed data, malformed IPC,
unsupported firmware, duplicate actions, target changes, exact readback and
preserved neighboring bytes. They are host and receiver-contract evidence, not
proof of a physical manufacturing restore or firmware update.
