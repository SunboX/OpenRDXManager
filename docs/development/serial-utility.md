<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Serial utility development

`openrdx-serial` is a separate macOS native command for inspecting, preparing, and applying a dock manufacturing serial change. There is no GUI action for this operation. The utility preserves leading zeroes and selects an exact USB serial, vendor `1a5a`, product `0005`, and nonzero USB location. Ambiguous selection fails.

Serial mutation requires the dedicated OpenRDX 1.09 receiver protocol. OpenRDX 1.08 rejects its non-mutating capability probe, so the utility cannot change a serial on 1.08. Building this utility does not install firmware. Hardware serial writes and USB re-enumeration through this new utility have not been verified on a physical dock.

## Build and command syntax

From `native/rdx-service`:

```sh
cargo build --bin openrdx-serial
./target/debug/openrdx-serial --help
```

Use an authorized macOS Terminal process with root device permissions for live commands. A permission failure is a prerequisite failure; the utility does not escalate itself or bypass macOS authorization. Close other applications actively operating the dock. The utility shares the hardware service's exclusive ownership lock.

The examples use placeholders rather than a real dock identity. Replace `<CURRENT_USB_SERIAL>` with exactly twelve ASCII digits beginning with `00`, `<USB_LOCATION>` with its nonzero location in decimal or `0x` hexadecimal, and `<NEW_UNIT_SERIAL>` with exactly ten digits:

```sh
sudo ./target/debug/openrdx-serial inspect \
  --usb-serial '<CURRENT_USB_SERIAL>' --location-id '<USB_LOCATION>'

sudo ./target/debug/openrdx-serial prepare \
  --usb-serial '<CURRENT_USB_SERIAL>' --location-id '<USB_LOCATION>' \
  --new-unit-serial '<NEW_UNIT_SERIAL>' \
  --output-dir '/absolute/new/private/plan-directory'

sudo ./target/debug/openrdx-serial apply \
  --plan-dir '/absolute/new/private/plan-directory'
```

`--new-usb-serial` accepts the equivalent twelve-digit `00`-prefixed value as an alternative to `--new-unit-serial`; the two options cannot be combined. Output is JSON, including fixed error codes. Inspection reports `valid`, `erased`, or `corrupt`, the USB and readable record serials, their agreement, revision, and full-sector hashes. Opaque manufacturing bytes appear only in explicitly requested private files.

All device operations require no mounted media, a fresh complete RDX INQUIRY reply, drive LOG SENSE framing, and fixed `RDXM` mechanism diagnostics. The active-low GPIO5 cartridge sensor must report absent, and the mechanism must be idle. The GPIO2 CAM input and absence of an OS disk mapping are insufficient evidence of an empty physical bay.

## Preparation and reconstruction

Preparation reads all 4096 bytes of the manufacturing sector through 32 fixed 128-byte operations. It creates a new owner-only directory containing `sector.bin` and `plan.json`, syncs both files and directory entries, and never overwrites existing evidence. Paths must be absolute with no symlink components. Files must be regular, singly linked, mode `0600`, and owned by the effective user; the directory must be mode `0700` with the same ownership. Prepare and apply must therefore use the same effective user, normally root for device access.

For an offline full-sector capture, add `--sector-file '/absolute/full-sector.bin'` to `prepare`. The input must contain exactly 4096 bytes. A 256-byte manufacturing record is insufficient. Offline output explicitly says `offline-unverified-device`; apply still requires an exact fresh device read and the original USB location/serial. Offline preparation performs no device discovery or hardware access.

A valid manufacturing record changes only its ten serial bytes and four checksum bytes. Every other byte, including all 3840 neighboring sector bytes, must survive. A partly corrupt record is always refused.

An entirely erased 256-byte record requires explicit `--reconstruct-erased` during preparation. This reconstructs the receiver's documented stock defaults and marks `originalFactoryDataLost: true`. It cannot recover original factory dates, configuration, or identity data that was erased. The erased reconstruction flag is rejected for a valid or partially corrupt record. The surrounding sector may contain non-erased data and is preserved.

## Application and recovery evidence

Apply validates every plan field against its complete private backup before opening hardware. It pins the selected device, checks its actual USB ancestor again, reads the complete sector freshly, and requires exact equality with the backup. A GOOD response to the non-mutating capability command is required before mutation. Fresh physical-bay evidence is checked again immediately before the attempt journal is persisted.

`apply-attempt.json` is created and synced before the serial write. Its existence prevents another write from the same plan after success or an uncertain result. Do not delete it to retry; inspect the current state and create a new plan after resolving any failure.

After the receiver reports success, the utility rereads all 4096 bytes and compares them with the exact expected sector. Only then does it persist `readback-before-reset.bin` and issue the existing unit reset. It closes the disposable USB capture worker, waits for the replacement USB serial at the same physical location, and writes `applied.json`. Reset may disconnect before its GOOD completion arrives; the receipt reports that separately. A failed or mismatched flash readback never issues the unit reset. USB re-enumeration failure is reported as unverified rather than successful.

The native capture object lives in a disposable worker because macOS can terminate a capture owner while surrendering USB capture. The CLI releases and reaps that worker on success and failure, with bounded cleanup deadlines. It never exposes arbitrary CDBs, flash addresses, registers, firmware transfer, or eject operations through its user-facing commands or serial worker policy.

See the [operator guide](../serial-utility.md) and [serial protocol reference](../protocols/serial-utility.md).
