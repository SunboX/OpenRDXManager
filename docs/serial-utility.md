<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Serial utility

`openrdx-serial` is a separate macOS command for inspecting, preparing and applying a supported dock serial change. There is no GUI action for it. Serial writes require the dedicated OpenRDX 1.09 receiver protocol; OpenRDX 1.08 rejects its capability probe. Building the utility does not install firmware, and its serial-write/re-enumeration flow has not been verified on a physical dock.

## Inspect and prepare

Use an authorized macOS Terminal with the necessary device permissions. Close other applications operating the dock and remove its cartridge. Replace the example executable path and placeholders with the intended values:

```sh
sudo /absolute/path/to/openrdx-serial inspect \
  --usb-serial '<CURRENT_USB_SERIAL>' --location-id '<USB_LOCATION>'

sudo /absolute/path/to/openrdx-serial prepare \
  --usb-serial '<CURRENT_USB_SERIAL>' --location-id '<USB_LOCATION>' \
  --new-unit-serial '<NEW_UNIT_SERIAL>' \
  --output-dir '/absolute/new/private/plan-directory'

sudo /absolute/path/to/openrdx-serial apply \
  --plan-dir '/absolute/new/private/plan-directory'
```

The current USB serial contains exactly twelve ASCII digits beginning with `00`; the new unit serial contains ten digits. USB location is a nonzero decimal or hexadecimal value. Preserve leading zeroes. Prepare and apply must use the same effective user, normally root for device access.

Preparation writes a new private plan and complete-sector backup without overwriting existing evidence. Apply requires the original serial, USB location, empty physical bay, compatible receiver and unchanged sector. A partly corrupt record is refused.

## Interrupted or uncertain results

`apply-attempt.json` prevents another write from the same plan. Do not delete it to retry: inspect the dock and resolve the failure before preparing a new plan. Flash readback must match before reset, and USB re-enumeration must be verified before completion is reported.

An entirely erased record requires explicit `--reconstruct-erased` during preparation. This writes stock defaults and marks the original factory data as lost; it cannot recover original identity, dates or configuration. Offline preparation likewise does not prove a live device can accept the change.

See [serial utility development](development/serial-utility.md) for building the command and [the serial protocol reference](protocols/serial-utility.md) for full options, record preservation and validation details.
