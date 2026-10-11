<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows macOS cartridge format fix — 2026-10-09

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

## Cause and scope

The reported `unsafe-volume-topology` failure stopped during format validation,
before a layout or filesystem write. Windows' ordinary native topology guard
rejects every EFI partition. macOS Disk Utility created an unused EFI partition
followed by Apple HFS data on the selected cartridge, so that conservative guard
also rejected an otherwise non-system cartridge.

Read-only Windows storage evidence on 2026-10-09 identified RDX Disk 1 as GPT,
3,000,588,787,712 bytes, with `IsBoot=false` and `IsSystem=false`. Its EFI partition
starts at byte 20,480 and is 209,715,200 bytes long. The HFS partition starts at
209,735,680 and is 3,000,244,813,824 bytes long. These are fixture inputs, not proof
that a physical format has succeeded.

## Implementation

- `native/rdx-service/windows-native/src/native/mac_layout.rs` permits a separate
  **format-only** proof for exactly EFI plus HFS/APFS GPT entries. It requires
  bounded, aligned, non-overlapping extents, distinct identities, and no protected
  partition flags. Disk Utility's LBA-40 EFI start is accepted.
- `native/rdx-service/windows-native/src/native/vds/disk_safety.rs` requires exact
  disk number, capacity and GPT identity, positive online evidence, and no Windows
  system, boot, paging, hibernation, crash-dump or other active/unknown role.
  Incomplete evidence fails closed. The query runs in the existing bounded worker.
- Protocol identity, medium identity, layout and protected host paths are checked
  again. The service uses this proof only for confirmed formatting. Native
  preflight and the layout-write boundary also repeat the guard.
- Ordinary rename, write/read and eject proofs are unchanged. Linux/macOS retain
  their existing formatting revalidation policy. No renderer privilege changes.

The role distinctions follow Microsoft's [VDS disk flags](https://learn.microsoft.com/en-us/windows/win32/api/vds/ne-vds-vds_disk_flag)
and [disk properties](https://learn.microsoft.com/en-us/windows/win32/api/vds/ns-vds-vds_disk_prop).

## Verification

Tests ran in `C:/Users/afiedler/rdx-status-tab-20261009`, an isolated local copy of
the shared source, with the same immutable firmware fixtures.

- Shared service: `cargo test --manifest-path native/rdx-service/Cargo.toml --all-features`:
  551 passed, exit 0.
- Windows companion: `cargo test --manifest-path native/rdx-service/windows-native/Cargo.toml --all-features`:
  110 passed, exit 0.
- Both crates: all-target/all-feature Clippy with `-D warnings`, exit 0.
  Shared service no-default-feature Clippy also passed.
- Focused application tests (utilities, labels, optical-volume classification,
  connection-to-Status behavior): 37 passed, exit 0.
- `npm run smoke`: real Electron renderer mounted and service ready, exit 0.
  This unprivileged smoke is not hardware proof.
- Both Rust formatting checks, `npm run format:check`, and focused `git diff --check`
  passed. Changed hand-written files remain below 1,000 lines.

The temporary local read-only probe passed on the exact selected dock at 13:41 UTC:
ordinary topology was `BootOrSystem`, format-only topology was `Simple`, writable
was true, and capacity matched 3,000,588,787,712 bytes. It did not mutate the device.
Local evidence files use the `mac-layout-` prefix in the verification directory.

## Follow-up: stale revision after layout dispatch

The user's subsequent format attempt at 13:41:33 UTC reached layout writing,
then failed with `stale-device-revision` during finalization. The ordinary registry
identity comparison included the pre-format mount/filesystem/topology, so replacing
the EFI/HFS layout invalidated the service's own continuation before VDS formatting.
Read-only Windows storage inspection found one Microsoft basic-data GPT partition
at offset 1,048,576, length 3,000,586,207,232, on the same non-system RDX Disk 1.
No filesystem was reported: the cartridge was RAW, not successfully formatted.

The follow-up fix arms a one-shot Windows continuation only after a successful
layout write by that resolved lease. Fresh protocol, cartridge identity, capacity,
writability and ordinary safe-topology proof remain mandatory; only the host fields
changed by that operation are normalized for the existing registry comparison.
Unrelated operations retain the original full comparison. macOS's verified combined
formatter retains its existing completion policy.

The Windows native handle separately retains the exact generated disk signature/GUID,
partition identity, extents, medium generation and capacity. It consumes this private
proof once and requires both the disk layout and fresh sole-volume extent to match
before VDS dispatch. Missing proof, partition replacement, stale EFI volume stacks,
protected flags, and multi-volume/multi-disk shapes cannot authorize formatting.
Post-format readback remains read-only and never repeats a filesystem write.

Follow-up verification passed: 553 shared-service tests, 112 Windows companion tests,
37 focused application tests, both all-feature Clippy checks, shared no-default-feature
Clippy, both Rust formatting checks, `npm run format:check`, focused diff checking,
and a rebuilt Electron smoke test. Evidence uses `format-continuation-` filenames in
the verification directory. The updated visible app was launched from
`C:/Users/afiedler/rdx-launch-20261009-e9099be` at 13:58:20 UTC and reported native
hardware access available.
Computer Use inspection confirmed the real connected-dock window selected Status,
reported 3.00 TB cartridge capacity, and showed the filesystem as not reported.

The agent did not repeat the physical format or perform firmware writes. A successful
end-to-end hardware format remains unverified; the user's failed attempt changed the
cartridge partition layout and must not be described as a completed filesystem format.
