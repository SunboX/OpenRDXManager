<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Vendor migration protocol and qualification

## Current result and scope

Manager distinguishes missing, malformed, renamed and mismatched release
manifests. Vendor `2.83 → OpenRDX 1.07` is a first installation, not a numeric
firmware downgrade. The native operation now includes the documented
compatibility-receiver route, a temporary receiver that restores exposed unit
records, and the ordinary update to the unmodified published release.

The first physical attempt on 2026-09-11 programmed the temporary receiver but
failed before preserved-record verification. A later ordinary retry was interrupted
by a host protocol-validation defect. The dock subsequently enumerated as the
TI ROM loader. The original private recovery bundle passed an independent
read-only receipt, journal and artifact integrity check after the failure.
At 16:26–16:27 UTC, built-in Manager recovery completed on that dock without J7:
the final public 1.07 release was installed, the native controller verified the
restored records, and independent IORegistry confirmed revision `0107` with the
original USB serial. This establishes the recovery route on that dock; a new
uninterrupted vendor-2.83 first installation remains unqualified.

See [the physical failure and recovery checkpoint](../evidence/firmware-first-installation-20260911/physical-recovery.md).
Compiled ARM execution with a modeled SPI boundary is supporting evidence, not
successful hardware installation or final executable-content readback.

## Corrected OpenRDX record verification

Vendor READ BUFFER (`3C`) is valid only for the source capture. The temporary
receiver and published 1.07 do not implement that opcode. Their existing TI
READ FLASH (`E7`) command provides the required read-only verification over BOT:
128 bytes at `0x3E000`, 128 bytes at `0x3E080`, and 64 bytes at `0x3F000`.
Manager compares all 320 bytes with the preserved package, including checksums
and opaque fields, while retaining the exact serial/location binding. No generic
flash-address API is exposed. See [actual-byte dispatcher evidence](../../analysis/migration-bootstrap/FLASH_READ_EVIDENCE.md).

The first failure also exposed a native terminal-event validation bug, and the
ordinary retry exposed a second JavaScript validator that rejected the direct
`firmware-validating` to `firmware-writing` transition. These are corrected in
source with deterministic regressions. The recovery checkpoint distinguishes
the earlier host executable-loading stalls, completed checks, remaining test
failures and the subsequent successful physical recovery.

## Documented first-installation sequence

The [OpenRDX installation manual](https://github.com/SunboX/OpenRDX/blob/main/docs/getting-started/installation.md#inspect-then-install)
and its [PowerShell updater](https://github.com/SunboX/OpenRDX/blob/main/scripts/rdx_manager_firmware_update.ps1)
explicitly distinguish `-InstallOpenRDXOnCompatibilityReceiver` from the normal
`-InstallOpenRDX` operation. They specify:

1. Verify the image, exact device identity, empty bay and USB location.
2. Apply the two fixed compatibility setup requests, then stage the complete
   container using mode 04. Require GOOD on the first fifteen chunks and exactly
   `07/74/08` on the final chunk. Do not send mode 05 to the vendor receiver.
3. Prompt for a USB power cycle with J7 open. Require the unique `0451:926B` ROM
   loader at the original physical location.
4. Program through TI's ROM protocol, then prompt for another power cycle with
   J7 open and verify the returned OpenRDX receiver.

Manager uses Apple IOHID/IOUSBHost interfaces for this Windows-documented
programming sequence. Because ordinary ROM setup erases the whole SPI chip,
Manager first saves a durable private capture and personalizes its pinned
restoration receiver. After record readback, it sends the original release
through the normal OpenRDX mode-04/mode-05 updater and verifies the records again.

The native implementation is in `src/service/hardware/migration.rs` under the
native service, with fixed command builders in `src/protocol/cdb.rs`. It accepts
no arbitrary command/address input from the renderer. Both power-cycle steps
require an acknowledgement bound to the exact active operation and stage;
automatic re-enumeration alone cannot start writes while the operator is about
to follow an unplug prompt. The firmware operation remains locked throughout.

The ROM stream transfer and reset follow TI GUI evidence: successful bulk
DeviceIoControl is followed by ResetDevice(false), then an unplug/replug dialog.
This ordering is not a separate proof of internal SPI completion. Native short,
failed or uncertain programming outcomes stop without tail replay or reset.

The user reports that Windows vendor RDXManager installed OpenRDX 1.06 onto vendor
2.83. That observation must be retained. The captured 2.83 binary is evidence of
one firmware image; the revision string alone does not prove that every running
2.83 receiver has those same bytes.

## Findings from the captured firmware

The retained firmware payload has SHA256
`4854e7c7b61c286c2a969adb9670151a627c6c079aa71f98073bfb1bf8ff9f21`.
It is available in the sibling firmware workspace's `Firmware/` directory and the
local private-firmware analysis tree. The relevant actual runtime addresses are:

| Address                                    | Evidence                                                                 |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| `0x08004884`                               | WRITE BUFFER dispatcher                                                  |
| `0x0800A0E8` / `0x08000AEC`                | update wrapper and streaming image parser                                |
| `0x0800B9B0` / `0x0800AB7C` / `0x0800531C` | signature-validation entry, wrapper and RSA/SHA validation               |
| `0x08000E32..0x08000E54`                   | authentication precedes boot-header commit; rejection reports `0x2D`     |
| `0x0800B648`                               | commits the saved first four boot bytes only after successful validation |
| `0x080034C4`                               | SEND DIAGNOSTIC; ordinary unit-reset CDB is `1D 05 00 00 00 00`          |

Executing the captured parser and cryptographic checker in an ARM emulator accepts
the original signed vendor 2.83 container. It rejects the published OpenRDX 1.06
container and the current 1.07 container at the signature check. This discrepancy
with the user's successful Windows installation remains unresolved; it is not
evidence that the reported installation could not have happened.

The ordinary updater erases only the lower 64 KiB and withholds the boot header
until validation. The diagnostic reset sets the normal system-reset flag. Whether
that reset reliably enters ROM after an uncommitted update on the connected dock
requires physical verification. The firmware workspace contains external SPI firmware,
not a dump of the on-chip ROM.

## Why the temporary receiver carries identity records

TI states that the ROM loader erases the entire SPI chip before programming.
Its ordinary formatted firmware stream fits within the supported 65,535-byte
host limit; that stream cannot simply carry a 256-KiB raw flash backup.
See [TI's flash-programming requirements](https://e2e.ti.com/support/interface-group/interface/f/interface-forum/1058950/tusb9261-tusb9261).

The prototype therefore embeds a small restore package in a temporary receiver:

1. Capture fresh factory, USB identity, INQUIRY, drive LOG SENSE and MODE SENSE
   responses from one selected vendor 2.83 dock.
2. Reconstruct the known manufacturing and operational fields, bind them to that
   dock's exact serial, and prepare the complete receiver image before a write.
3. Program the temporary receiver using the ordinary ROM stream.
4. Restore and reread both records before identity initialization or USB startup.
5. Use the receiver's normal update operation to install the unmodified OpenRDX
   release container; verify activation through the existing update/readback path.

These stages are now connected in the native firmware operation. Steps requiring
hardware remain unqualified. J7 is a potential recovery measure; the documented
normal route keeps it open.

## Semantic reconstruction is not a raw backup

The authoritative field map is
[high-flash-configuration.md](high-flash-configuration.md).
READ BUFFER mode 2, ID 2 returns 172 bytes; ID 10 returns 32 bytes. Together with
standard INQUIRY, these expose every identified version-6 manufacturing field,
including all three opaque 16-byte factory fields. Those opaque bytes are retained
without interpreting or printing them.

Drive LOG SENSE page `0x20`, parameter `0x0001`, supplies the load count. MODE
SENSE page `0x34`, byte 4 supplies the effective operation mode. The prototype
also validates the bounded raw responses against the derived JSON values.

The unexposed 48 manufacturing bytes and 55 state bytes are reconstructed as
zero. Stored mode zero is reported by the vendor firmware as effective mode one,
so the reconstruction cannot distinguish those two original representations.
The capture preserves exposed runtime fields; it cannot establish whether the
vendor originally loaded them from valid flash or from its compiled defaults.

Only the researched version-6 source USB `1A5A:0006` family with hardware selector
`0x38` is admitted. The pinned receiver's actual runtime descriptor changes to
`1A5A:0005`, while its preserved manufacturing USB response remains PID `0006`.
Readback requires that distinction plus unchanged serial, VID and physical port.
The descriptor source `usb_chap9.c` is pinned by SHA256
`d68248dc8c9fb27e5a82d05662e7e8df5ea042239aabe0b5a81a200d67d49406` in the bootstrap
source-input manifest. Product enumeration is retained as either the
captured `0x38` or the vendor's compiled-default zero; this is a separate metadata
field, not the hardware selector. Other layouts must be researched before
extending the prototype.

## Fixed restore package

The package is exactly 384 bytes. All integers are little-endian.

| Offset              | Field                                                      |
| ------------------- | ---------------------------------------------------------- |
| `0..7`              | ASCII `RDXMIG01`                                           |
| `8..9`              | schema 1                                                   |
| `10..11`            | header length 64                                           |
| `12..15`            | total length 384                                           |
| `16..19` / `20..23` | manufacturing address `0x3E000` / length 256               |
| `24..27` / `28..31` | state address `0x3F000` / length 64                        |
| `32..63`            | SHA256 of bytes `64..383`                                  |
| `64..319`           | reconstructed manufacturing record with four-lane checksum |
| `320..383`          | reconstructed state record with four-lane checksum         |

`analysis/scripts/build_migration_profile.py` is an offline builder. It has no
USB, SCSI or SPI interface. Its output uses exclusive creation and mode `0600`;
it refuses to replace existing evidence. Personalized images and snapshots belong
outside the repository because they contain per-unit fields.

Before any erase-capable request, the application must move the validated snapshot,
personalized image and operation journal into a private persistent recovery
directory, sync their files and directory entries, and reopen/verify them. The
temporary files used during this investigation are analysis inputs, not a durable
recovery store; `/tmp` must not be the only copy during a hardware migration.

The offline [recovery bundle API](../../analysis/prototype/RECOVERY_BUNDLE.md) now
implements exclusive private creation, file/directory syncing, reopening and
independent validation. It retains the original capture, source binding,
personalized bootstrap and unmodified published 1.07 release pair. Its receipt
must be retained separately, and the owning controller must obtain fresh source
identity/location evidence before a transition. This API does not perform that
transition or qualify the hardware route.

The template contains one invalid 384-byte placeholder. An unpersonalized template
must fail before any SPI access and must not start USB. The host replaces only that
slot and updates the TI runtime checksum; an explicit template SHA256 is required.
This operation does not modify the original OpenRDX release container.

The host transport also normalizes the embedded package back to the blank slot
and checks the resulting template hash. It rejects a bare template, changed
executable code or a profile whose serial differs from the source binding before
USB enumeration. On macOS, the HID reports require native IOHID access while
libusb claims only the separate vendor bulk interface. Both must identify the
same USB parent. See [the prototype transport notes](../../analysis/prototype/README.md).

## Qualification boundary

Before claiming successful application migration, verify all of the following on the exact
selected dock: complete fresh snapshot, source-to-ROM physical USB location
binding, macOS access to both ROM interfaces, accepted full transfer, reset and
USB re-enumeration, restored identity/state, and final unmodified-release update.

The ROM transport's USB transfer result alone is not firmware verification.
Unknown setup or transfer outcomes require recovery assessment; they must not
trigger an automatic reset or an unbounded retry. A durable operation journal
must exist before the first erase-capable request. Native preparation creates and
independently reopens artifacts under the root-owned mode-0700
`/private/var/db/OpenRDXManager/recovery` directory before compatibility setup.
The operation admits only the pinned public release and validated source layout;
other receivers and images retain the existing unsupported-route error.

## macOS capture evidence, 2026-09-11

Read-only standard USB descriptor requests successfully matched the selected
dock's serial and physical libusb location (bus 0, port 2). Fresh IORegistry
evidence still reported vendor revision `0283` afterward. No ROM programming
interface was accessed.

The isolated factory collector failed before its first SCSI read. With native
administrator approval, the legacy SCSI plug-in returned `0xE00002C7`
(`kIOReturnUnsupported`), so the normal USB fallback ran. Device capture and
configuration succeeded, but `IOUSBHostInterface` initialization returned
`0xE00002C9` (`kIOReturnInternalError`). The collector's final diagnostic was
`stage: acquire-scsi`, `nativeError: other`; no snapshot file was created.

System Settings showed Terminal with Full Disk Access and the calling ChatGPT
app without it. [An exact matching Apple Developer Forums report](https://developer.apple.com/forums/thread/844378)
describes successful Terminal-root access and failed administrator AppleScript
access, with Full Disk Access resolving the interface failure. Apple's DTS
engineer confirms an FDA check exists but distinguishes this internal error
from the missing virtualisation entitlement error. An [earlier report](https://developer.apple.com/forums/thread/774497)
describes the same mass-storage interface failure from a root launch daemon.
The user subsequently stopped the running Manager and ran the exact pinned
collector from Terminal with `sudo`. It succeeded: initial and final INQUIRY
matched, factory-info and USB-identity responses were complete (172 and 32
bytes), and drive LOG SENSE and MODE SENSE responses parsed successfully. The
legacy plug-in diagnostic remained present, proving that this unsupported
legacy route is not itself a fatal capture error. No firmware was written.
Because both the launch context and running-Manager state changed, this result
does not isolate Full Disk Access as the sole cause. An internal native error
must not automatically be reclassified as permission denied.

The actual capture passed the offline record decoder. A private recovery bundle
and separate receipt were created under the user's persistent
`Library/Application Support/OpenRDXManager/recovery` directory, synced and
reopened successfully. Fresh standard USB descriptors and an independent
IORegistry USB-parent observation matched the capture's identity and location.
No private response bytes were placed in the repository.

The compiled ARM restore code was then exercised with that exact private package
at the modeled SPI boundary. Exact two-record restoration, a second boot with no
record writes, recovery from a partial program and rejection of failed readback
all passed. This is actual compiled-code evidence with real input fields, not a
physical SPI/USB installation result.

The read-only collector now also supports explicit `--readback`: it requires
reported revision `0107` and produces kind `openrdx-0107-restoration-readback`.
The default remains vendor `0283` source capture. Neither capture format claims
firmware-content verification. The offline
`analysis/prototype/tusb9261_restoration_readback.py` comparison reopens the
receipt-bound bundle and requires every factory/USB response byte and the
reconstructed manufacturing/load-count/effective-mode records to match. It
requires a separate postboot observation and fresh supplied identity/location;
it cannot establish freshness from JSON alone. The native operation obtains fresh
same-lease captures and independently compares the fields before the final
release transfer and again after its finalizer.

Offline profile regression command:

```sh
python3 -B analysis/scripts/test_build_migration_profile.py
```
