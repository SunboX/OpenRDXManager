<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Migration

Installing OpenRDX on a vendor-firmware dock is a first installation. It uses a different workflow from an ordinary OpenRDX update. The documented Manager route is for the admitted vendor 2.83 dock and exact published OpenRDX 1.07 release on macOS; other combinations must satisfy their own current capability checks.

## First installation

1. Select the intended dock and keep its cartridge bay empty.
2. Place the matching release BIN and JSON together, then select the BIN in **Utilities → Update Firmware**.
3. Follow the guided installation. Manager saves private unit records before proceeding.
4. At each USB power-cycle prompt, reconnect to the same port and click **Continue after reconnecting**. Keep J7 open during the normal guided procedure.
5. Wait for final firmware and preserved-record verification. Keep the saved recovery data even after success.

An uninterrupted first installation through this Manager workflow remains unqualified on physical hardware. A recovery through Manager completed on one dock on macOS on 2026-09-11. That result does not establish every device, port or platform combination. See the [migration reference](protocols/vendor-migration.md) for preservation limits and the recorded qualification.

## Recover an interrupted installation

If the dock appears in TI recovery mode, open **Recover a dock in TI ROM mode**, even if the normal RDX list is empty.

1. Choose the saved unit record and the connected recovery-mode dock.
2. Confirm that the saved record belongs to that physical dock. The bootloader's generic identity cannot establish this association for you. If several bootloaders are connected, disconnect the others to identify the intended one.
3. Start recovery. The dock may initially use any USB port; keep it on the selected port for this attempt.
4. Follow the power-cycle prompt and explicitly continue after reconnecting.
5. Wait for firmware and original-record verification. Keep any failure reason if the result is incomplete.

Recovery requires valid saved data for that unit. Missing or damaged records cannot be inferred from the bootloader. Do not discard an interrupted attempt's records or blindly repeat writes after an uncertain result.

The observed physical recovery used the original port. Different-port selection has software test coverage, rather than a separate live-device result. See [recovery implementation notes](development/migration-recovery.md) and the [physical recovery record](evidence/firmware-first-installation-20260911/physical-recovery.md).
