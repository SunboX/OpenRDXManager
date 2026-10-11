<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# MacOS Windows firmware investigation — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

This report records the diagnostic checkpoint before the offline repair candidate
and transfer commits. For their identities and the next native-Windows session,
see [the consolidated handoff](native-windows-firmware-handoff-2026-10-08.md).

## Result and remaining blocker

The requested successful ordinary firmware update on both operating systems is
**not yet achieved**. The exact selected receiver rejects the same serial
capability query on macOS and Windows. Windows continues to reject it after the
user-confirmed full disconnect/reconnect. No firmware download, activation,
manufacturing write or serial write was issued during this investigation.

Two identical reads of the complete boot region establish that the SPI contains
the original shared 1.10 image, not either development correction. Two complete
256 KiB reads before and after the user-confirmed cold start establish a current,
unchanged same-unit backup. This is new hardware evidence; revision `0110` alone
could not distinguish the three 1.10 images.

The observations do not support a Windows-only capability-query problem. They
also do not establish that ROM recovery is the only possible next route. A safe
first installation of the initializer correction remains unverified. Removing
the host query gate would not repair the original receiver's corresponding
download admission check.

## Scope and target

The user authorized application/firmware changes, Parallels USB reassignment,
and the goal of working firmware updates on macOS and Windows. The handoff was
used as reference material. Original inputs, previous attempts and pre-existing
changes in both repositories were preserved.

- Receiver: TANDBERG RDX, unit `7820999743`, USB `007820999743`, VID/PID `1A5A:0005`.
- macOS USB location: `0x00200000`; Windows target was freshly checked as
  `\\.\PHYSICALDRIVE1` with the exact serial-bound PNP identity.
- INQUIRY/VPD and the physical mechanism diagnostic confirmed revision `0110`
  and an empty idle bay before and after every completed probe.
- Windows 11 VM: `{25baf3c7-1a5b-4327-a4f1-776d4e92508f}`.
- Final assignment: Windows 11. `RDXmon` was restored to its initial running
  state after each Windows probe; no diagnostic hardware process remains active.

Private evidence directory:
`/Users/afiedler/Downloads/OpenRDX-Mac-Windows-20261008T074632Z`.
Its complete SPI snapshots contain unit-specific records and remain outside Git.

## Matched capability queries

All completed probes sent manufacturing then serial on one retained handle/lease.
Both capability frames have CDB length 10, no data transfer, zero transfer length
and zero payload. Windows additionally compared direct and buffered SPTI.

| Query                    | CDB                    | macOS                                   | Windows direct and buffered             |
| ------------------------ | ---------------------- | --------------------------------------- | --------------------------------------- |
| Manufacturing capability | `3B024D00000100000000` | GOOD, zero bytes                        | GOOD, zero bytes                        |
| Serial capability        | `3B025300000100000000` | CHECK CONDITION, `05/24/00`, zero bytes | CHECK CONDITION, `05/24/00`, zero bytes |

macOS completed all eight fixed reads at `08:10:33Z`, with native service response
2 (`TASK_COMPLETE`) and confirmed capture release. The legacy plugin acquisition
failed, but the production USB capture fallback successfully executed the reads.
Windows host IOCTLs succeeded (`HostError=0`); this is separate from SCSI status 2.
INQUIRY/VPD allocation was 254 on macOS and 96 on Windows; the matched query
frames themselves were identical. CDB labels in the Mac report come from reviewed
source construction. No raw USB packet capture or live RAM measurement was made.

The first two Mac diagnostic attempts failed before any device command because
the investigation's private reader admitted a 268-byte initialization frame,
while the production format contains 524 bytes. This diagnostic defect was
corrected and regression-tested; those failures are not application/USB faults.

Evidence: `mac-probe-attempt-3/result.jsonl`, its native stderr and exit code;
`windows-production-order-result.json`, `windows-after-roundtrip-result.json`,
and `windows-after-coldstart-result.json`.

## Installed and corrected firmware identities

The fixed E7 read operation was reviewed against `scsi_handle_ti_defined_cmd`
in the firmware's `src/rdx_mount/scsi.c`. Read probes expose no OUT command,
unlock, erase or reset. Each complete image was read twice and compared byte for
byte before saving it. The boot header and runtime checksum also passed.

Boot region: SPI `[0, 61710)`, container `[0x18C, 0xF29A)`.

| Image                                    | Container SHA-256                                                  | Boot-region SHA-256                                                | Matches installed SPI |
| ---------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ | --------------------- |
| Original shared 1.10                     | `4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a` | `abf7a4156b605fbfd62d123543389ea013e9ceb9828e0a1d48f5bb37da1fa5c6` | Yes, exact bytes      |
| September 15 BOT candidate               | `879d97119d1510a1e2ab6392dd5ee135f883cf5fea1332dd8a867efb48618f06` | `58066055260df9921c8136cfd1cd6f805ba77e8ab89247a1558a053cc1f81b9c` | No                    |
| September 16 initializer + BOT candidate | `c6f4334552dfab7443948f22cfb11a9218b01394eb76f06b147edc4e748c799c` | `3191b86bded273ab8099bcaad63d878057f023cecb29aab13e03b883fdd11264` | No                    |

The latest complete six-file bundle was copied from the Windows candidate
directory into `corrected-candidate/`, and its 62,110-byte container hash was
independently verified on macOS. The source initializer correction was already
present before this investigation; it was not replaced or version-bumped.

Full SPI backup, 262,144 bytes:
`027e4a699c5589bda268b92efc3f76143b9790a18e13da43381957aeb5e3ee32`.
The `08:37:52Z` post-cold-start snapshot exactly matches the `08:26:25Z` snapshot.
Each was independently read twice. Copies are stored in restricted Windows
evidence directories and Mac directories with mode 0700/files 0600. This proves
backup content/consistency; restoration of that full image has not been tested.

Evidence: `installed-firmware-comparison.json`, the two full-snapshot summaries,
and private snapshot result files. No private sector bytes are included here.

## Mac reference and source admission

The user identified the previously working route as `npm start` from this project.
The precise successful transaction's executable/image hash and date are still
unbound. Preserved Mac logs contain successes on September 11–13, before the
initializer candidate from September 16; they do not prove that candidate was
installed on the selected unit. Do not assign those historical opaque device IDs
to today's USB serial without further evidence.

| Preserved artifact                              | SHA-256                                                            | Evidence limit                                               |
| ----------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------ |
| Development `out/native/macos/openrdx-hardware` | `d11337f11a823a5c782b08c0f3a7c88332074e29e851f690928948b441f284ad` | September 13 staged file; not transaction-bound              |
| Development `target/debug/openrdx-hardware`     | `57912571720edb79cead152db6b75e8d3868baa2934cef33210d8d4cff982c19` | Preserved before compilation in an isolated target directory |
| Installed and packaged Mac service              | `5183fe7207402886000db7d1799630119d99b12ed5359907e8dfeb358e55c53e` | Same August 29 service in both app locations                 |
| Windows mirror service                          | `cee88af694c00c7d110ab71aa31f73b72ef427376949fd67a00fddb795a8ac1e` | October 8 binary; no firmware operation invoked here         |

The current Manager HEAD is `c7f30d3339adf62704b1bf8f8f9ffed3c175b037`.
Its shared `firmware_interlock.rs::require_ready` calls both queries for installed
revision 110 before `firmware-writing`. The earlier `afd3649` source did not have
that gate. Dates and preserved symbols support a development-build admission
difference; they do not prove a transport difference or pin the historical run.
The Windows mirror's gate source matched the original current HEAD byte hash
`092da20410bc5d2514833c31c2893c95922318cd723014ce7f22f428882f5d21`.

Source and byte-checked TI comparator instruction listing show a manufacturing-latch
check before both serial capability and ordinary mode-4 download admission.
Thirty relevant instruction rows matched the actual installed runtime bytes.
The original latch lacks a boot initializer; the already corrected firmware
uses `= FALSE`, with a real TI-generated zero `.cinit` record. This remains a
verified source/build defect and plausible explanation, not a live RAM reading.
The successful manufacturing query itself does not inspect the latch or prove
that all download/activation/serial-mutation state is inactive.

See the installed receiver admission instruction listing,
`src/service/hardware/firmware_interlock.rs` under the native service,
and the firmware repository's `rdx_manager_protocol.c` / `rdx_manufacturing.c`.

## Hardware timeline, UTC

| Time            | Action / evidence                                                                                          |
| --------------- | ---------------------------------------------------------------------------------------------------------- |
| 07:57:48        | Windows manufacturing-then-serial comparison, both SPTI routes                                             |
| 07:59:12        | Exact dock reassigned from Windows to macOS; ownership confirmed                                           |
| 08:10:33        | Corrected fixed Mac probe: same rejection, before/after identity and bay valid                             |
| Before 08:16:38 | Exact dock returned to Windows; ownership recorded                                                         |
| 08:16:38        | Boot region read twice; original shared image identified                                                   |
| 08:23:38        | Fresh Windows query pair after Mac roundtrip; same result                                                  |
| 08:26:25        | Complete SPI read twice and saved with restricted access                                                   |
| Before 08:35:45 | User confirmed full power/USB disconnect and reconnection; physical voltage was not independently measured |
| 08:35:45        | Fresh Windows query pair after that start; same result                                                     |
| 08:37:52        | Complete SPI read twice again; identical to pre-cold-start snapshot                                        |

USB capture and release can cause storage-driver rematching; Parallels reassignment
changes sessions. No deliberate reset CDB was sent. All these observations must
remain distinct from the user-operated power interruption.

## Changes and verification in this investigation

- Added this report and isolated bounded diagnostic sources/evidence outside the
  repositories. No arbitrary-CDB interface was added to the application.
- Corrected an inaccurate comment in `firmware_interlock.rs` that attributed
  update/serial inactivity to manufacturing GOOD. Executable gate behavior is
  unchanged. Existing unrelated modifications remain intact.
- Mac diagnostic: six deterministic tests passed; Clippy with warnings denied
  passed. The actual 524-byte identity-frame regression was observed failing
  before correction and passing afterward. Real fixed probe exited 0.
- Windows diagnostic: query allowlist rejected 27 forbidden frames; bounded
  boot/full-SPI allowlists passed before live use. Fresh result files/claims
  were used throughout; previous attempts were not removed or overwritten.
- Shared native interlock test passed through `npm run native:test -- firmware_interlock`
  in an isolated Cargo target directory, including after the comment correction.
- Firmware suite: 302 tests run, 9 skipped, exit 0 with the matching Xcode 26.5
  SDK. The initial default SDK27/linker incompatibility failed host C linking;
  it was resolved per process without changing SDK files or firmware source.
- Real TI ARM CGT 5.2.9 initializer tests on macOS: 2 passed, exit 0.
- `npm run format:check` and Cargo formatting check passed. No runtime behavior,
  main-process lifecycle or renderer change was made, so no new Electron-launch
  claim is made from these tests.
- No commit, push, release, installer generation or firmware installation.

## Required next evidence

The first installation of the corrected receiver remains the blocker for normal
updates. Any next method must establish its precise admission path, preserve the
selected receiver's records and verify written bytes and post-boot identity.
The retained full SPI backup and corrected six-file bundle provide a concrete
baseline for that work. The firmware repository's J7/full-image procedure is
explicitly experimental for this backup and has not been validated by this run.
It must not be treated as an automatically authorized, proven recovery recipe.

If a successful ordinary Mac transaction can be reproduced, pin its executable,
starting state and selected image and correlate its actual transfer/finalization
evidence with this unit. Once the correction is verifiably installed, successful
ordinary updates and preservation/readback still need to be demonstrated on
both operating systems before the user's goal can be reported complete.
