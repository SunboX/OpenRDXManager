<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Troubleshooting

Keep the displayed failure reason and support ID. Before retrying, refresh the dock's status and check whether the previous operation changed the device or media.

## Hardware service unavailable

Use the service setup or recovery action offered by the application. A running window alone does not establish device access. For source builds, check [installation](installation.md) and [macOS development access](development/macos-hardware-access.md). On Windows, the native runtime and required raw-device privileges must be available.

## Dock missing or disconnected

Check the USB connection, use **Scan for RDX devices**, and select the dock again when it returns. Cartridge spin-up can delay discovery. In a virtual machine, ensure the intended USB dock is attached to the guest. Do not infer that a disconnected dock is empty or that an in-progress write failed without examining its recorded result.

## Operation will not start

- `operation-in-progress`: wait for the current operation or scan to settle.
- `stale-device-revision`: refresh and recheck the intended dock before making a new request.
- An unavailable capability: follow its displayed prerequisite or compatibility explanation.
- A firmware manifest error: restore the matching BIN/JSON pair and select the BIN again.

Some security actions remain explicitly unavailable. Formatting requires the exact confirmation and supported writable media; host format choices and required tools differ by platform.

## Firmware reconnect or migration failure

For `firmware-reconnect-failed`, reconnect the same powered dock and inspect its firmware revision before another attempt. Firmware may already be installed. See [firmware updates](firmware-updates.md).

If the dock is in TI ROM mode after a first installation, use the [migration recovery guide](migration.md#recover-an-interrupted-installation) and retain its saved unit records. Recovery cannot replace missing original factory data.

## Collect a support report

Use Help and the activity/report controls to retain the operation reason, support ID and relevant context. Review exported reports before sharing because device identities may be included. A cached status, accepted request or software test does not establish a completed physical operation.
