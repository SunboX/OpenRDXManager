<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Disable and enable cartridge access

## Overview

Once password protection or encryption exists, **Disable Access** closes the
current authenticated session. The UI changes to a red status icon and offers
**Enable Access**. Enabling asks for a valid cartridge password; success shows
a green icon and restores data access.

This is a lock/unlock operation. It does not remove protection, change the
password, decrypt all data, or reformat the cartridge.

## Internal flow

The Manager sends the appropriate cartridge-security/session command through
its `ScsiDevice` transport and updates the host volume layer. For encrypted
media, the software-encryption mount/path must also transition to the usable
state. For basic protection, the drive/cartridge access gate controls normal
I/O.

Expected result classes are:

- disable success: current access ends and protected status remains;
- enable success: credential accepted and read/write access follows its
  permission bits;
- bad credential: access remains disabled;
- media removal/device reset: authentication session can be lost and must be
  re-established after insertion.

The UI disables password-management controls while access is disabled; the
user must enable access with a valid credential first.

## Implementation details

Disable clears the Manager's current authenticated slot/session and tells the
security processor to close access. The software-encryption controller then
withdraws or changes the Dokan volume state. Enable first refreshes the eight
slot descriptors, derives the supplied password proof from drive-provided
salt/iteration parameters, submits authentication, and refreshes read/write
permission and mount state.

Deleting or disabling the currently authenticated slot is handled as an
explicit session-ending action. Media removal also invalidates the cached
session model, preventing stale credentials from being assumed valid for a
different cartridge.

## Protocol details

Session operations use SECURITY PROTOCOL IN/OUT:

| Phase                        | CDB                                   | Data                                  |
| ---------------------------- | ------------------------------------- | ------------------------------------- |
| read session/slot parameters | `A2 20 ss ss 00 00 00 00 10 00 00 00` | up to 4096 bytes in                   |
| derive proof                 | no SCSI command                       | two-stage PBKDF2-HMAC-SHA-256 on host |
| authenticate/close session   | `B5 20 ss ss 00 00 ll ll ll ll 00 00` | descriptor bytes out                  |
| verify new state             | SECURITY PROTOCOL IN `0xA2/0x20`      | descriptor refresh                    |

The reference Windows code shows selector `0x0020`/`0x0021` queries and
slot-indexed requests; stripped symbols prevent safely assigning every numeric
selector to enable versus disable. Success requires SCSI GOOD and a refreshed
state showing the requested access/permission. A wrong password normally
returns an authentication descriptor/status failure or CHECK CONDITION; it
does not fall back to unprotected access.

## PDF-derived exact UI sequence

With access enabled, the right side of the Encryption tab shows **Disable
Access**. Clicking it and acknowledging the confirmation closes access, shows
a large red `X` in the status area, and changes the action to **Enable Access**.

With access disabled, **Enable Access** opens an Input Password dialog. A valid
configured password restores the access allowed by that password's permission
bits, shows a large green check mark, and changes the button back to **Disable
Access**. A read-only password therefore restores read access but not writes.

While access is disabled, the change/remove/advanced buttons remain inactive.
The documented prerequisite for using them is to click **Enable Access** and
authenticate first. These UI state changes are confirmations of the refreshed
security state; they are not separate commands beyond the security transaction
described above.

Source coverage: Product Manual pp. 19-21 and 24.
