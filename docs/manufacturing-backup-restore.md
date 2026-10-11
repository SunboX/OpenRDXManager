<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Manufacturing backup and restore

Manufacturing backups preserve a dock's factory identity record. Use **Utilities → Backup manufacturing data** when the selected dock and service support it. Automatic backups also protect supported firmware-update and restore workflows.

## Create and keep a backup

1. Select the physically connected dock and remove its cartridge.
2. Start **Backup manufacturing data** and wait for its confirmed result.
3. Use **Open backup folder** to view the private store used by the native service.
4. Keep the original record and its integrity metadata together. Associate it with the physical dock and original unit serial.

Erased or corrupt records can be retained as evidence, but they cannot supply missing original factory data. A valid checksum on a replacement record does not establish that its identity is original.

## Restore an original record

1. Select the empty dock and choose a valid saved record by its original serial and date.
2. Type the original ten-digit unit serial and confirm that the backup belongs to this physical dock.
3. If the current identity differs, also confirm the explicit identity replacement shown in the form.
4. Start restoration and wait for complete verification. Manager saves the current sector before attempting the restore.
5. After verified success, power-cycle the dock to activate the restored identity.

Restore requires a compatible receiver that passes the live capability check. A firmware version string or building the software alone does not enable it. Availability and storage prerequisites can differ by platform; use the reason shown beside the action.

Restoration replaces the original record, including opaque factory fields; it does not synthesize lost factory data. Neighboring sector bytes must be preserved. The operation is not power-fail atomic, and failed or uncertain restores are not automatically retried. Keep the pre-restore backup if an operation is interrupted.

See [the record and restore reference](protocols/manufacturing-backup-restore.md) for storage and validation details, and [manufacturing verification](verification/manufacturing-verification.md) for recorded software and physical-test boundaries.
