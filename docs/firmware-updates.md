<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Firmware updates

Select the exact dock, remove its cartridge and open **Utilities → Update Firmware**. The application checks the image and receiver before admitting an update; unsupported formats and receivers remain blocked.

## Select an OpenRDX release

1. Keep the release `.bin` and its matching same-stem `.json` manifest together, with their original filenames. For example, `OpenRDX-v1-07.bin` belongs beside `OpenRDX-v1-07.json`.
2. Select the BIN through **Update Firmware**. If selection reports a missing or mismatched manifest, restore the matching pair and select the BIN again.
3. Check the selected dock and proposed update, then follow the displayed workflow.
4. Keep the dock powered and wait for firmware and identity verification to finish.

A version string alone does not make an image compatible. The application validates the release contents, current receiver and required factory-record backup. It rejects missing, changed or corrupt records where preservation cannot be established.

Vendor `.BIN` images use their own validation rules. Legacy USB2/SATA1 `.BIP` updates remain unavailable where their format is unproven. Do not rename another image type to bypass these checks.

## Reconnection and failures

A firmware reset can temporarily remove the dock from discovery. In a virtual machine, follow the reconnect guidance and attach the same USB dock to the guest while keeping it powered.

An accepted request is not a completed update. If the application reports `firmware-reconnect-failed`, firmware may already be installed: reconnect the same dock and inspect its version before considering another attempt. Keep the failure reason and support ID. An uncertain result is never a confirmed success.

Installing OpenRDX on vendor firmware uses the separate [migration workflow](migration.md). If an interrupted installation leaves the dock in TI ROM mode, follow that guide's recovery section.

Implementation details and historical checks are in [firmware update development notes](development/firmware-updates.md), [the firmware protocol reference](protocols/firmware-update.md) and [verification](verification/README.md).
