<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# App usage

Select an RDX dock in the device rail before using its workspaces. **Auto Scan** refreshes discovery when devices change. If a dock disconnects and returns, select it again and wait for current status.

## Status

The Status workspace shows the selected dock's identity, firmware revision and available cartridge information. Missing or unsupported values remain unavailable; they do not mean zero or a healthy device. Check that the displayed dock and cartridge are the ones you intend to manage.

## Encryption

The Encryption workspace shows protection and access capabilities. Some password, permission and encryption operations remain unavailable because their complete device behavior is not established. Follow the capability explanation beside the action. A forgotten credential cannot be recovered, and resetting protection can affect access to existing data.

## Tests

Run one diagnostic at a time:

- **Self Test** checks host-to-dock communication and, with media inserted, the cartridge path.
- **LED Test** runs the drive and cartridge indicator sequence, then restores normal LED control.
- **Write/Read Test** requires suitable writable media and reports its progress and result.

Wait for a final result. A green result indicates a confirmed pass; a disabled button or an accepted start request does not establish success. Cancellation is available only while the operation is within its safe cancellation boundary.

## Utilities

Utilities provides the actions supported by the current dock and platform: firmware updates, cartridge formatting and eject, drive settings, and manufacturing backups or restore.

Formatting destroys existing cartridge data. Choose the filesystem offered by the current host, check the exact dock and cartridge, and complete the displayed confirmation. macOS filesystem encryption is separate from the RDX cartridge-protection protocol.

Use **Safe Eject** for normal removal. **Force Eject** has a separate confirmation because cached data may be lost. An eject succeeds only after the application verifies cartridge departure.

See [firmware updates](firmware-updates.md), [migration](migration.md) and [manufacturing backup and restore](manufacturing-backup-restore.md) for their specific requirements.

## Help and activity

The top bar opens Help, compatibility information, activity and service recovery. Keep the visible failure reason and support ID when reporting a problem. Exported support reports can contain device identities; review them before sharing.

See [troubleshooting](troubleshooting.md) for failed starts, unavailable services or a disconnected dock.
