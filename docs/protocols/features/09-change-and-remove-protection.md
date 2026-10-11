<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Change passwords and remove protection

## Change password

The Manager can replace the master or a named credential after authenticating.
Executable messages explain that one temporary password slot is used to change
passwords safely; if all slots are occupied, a slot must be made available.
The new and confirmation values must match, and the UI reports estimated
strength.

## Remove basic protection

**Remove Password Protection** authenticates, removes the relevant password
configuration and returns the cartridge to unprotected access. It does not
need the AES volume-removal path because stored payload data was never
encrypted.

## Remove AES-256-XTS protection

**Remove Encryption** removes encryption-related passwords/configuration and
then partitions/formats the cartridge. This permanently deletes encrypted
contents; the executable warns accordingly. A format failure can require a
reboot and retry.

## Passwordless reset

If setup allowed `Cartridge Reset and Erase All Encryption Configuration
Without a Password`, protection configuration can be cleared without the
credential. This is a recovery/erase path, not password recovery: existing
protected data is not revealed and can be destroyed.

Internally these operations sequence cartridge-security commands with host
volume unmount/format actions. Return failure at any stage is reported and
logged; the base security CDB is exact, while every stripped vendor selector
name is not.

## Implementation details

Password replacement needs a free temporary slot so the new verifier can be
created and validated before the old slot is removed. This explains the UI
error when all eight slots are occupied. The Manager refreshes the credential
table after every stage and ends the session if its authenticating slot was
removed.

AES removal additionally coordinates `RDXEncrypt`/Dokan teardown, physical
volume access, partition layout recreation and `FormatEx2`. Basic-protection
removal omits XTS teardown. Passwordless reset uses only the reset policy that
was stored during setup; it erases configuration rather than recovering key
material.

## Protocol details

Credential metadata and per-slot KDF parameters are read with SECURITY
PROTOCOL IN (`0xA2`, protocol `0x20`, selector in bytes 2–3, 4096-byte default
allocation). Create/change/delete/reset descriptors are sent with SECURITY
PROTOCOL OUT (`0xB5`, protocol `0x20`, payload length in bytes 6–9).

Change is therefore a multi-command transaction, not an atomic CDB:

```text
read slots -> allocate temporary slot -> derive/write new credential
           -> verify authentication -> remove old slot -> refresh table
```

AES removal continues with OS volume operations only after security-command
success. Any failed stage stops progression and is logged. Descriptor types
`0xC1..0xC5` and their parsers have reference coverage, but the complete selector table
is intentionally left unresolved.

## PDF-derived change and removal workflows

Before any change/removal action, disabled cartridge access must be re-enabled
with a current valid credential.

For **Change Password**, the user enters and confirms the replacement master
password, sees the `Poor` through `Very Good` strength estimate, confirms the
operation, and waits for the progress bar. The new password is effective when
the operation completes. If all eight slots are occupied, the implementation
needs one to be freed for its temporary-slot transition.

For **Remove AES 256 XTS Encryption**, the user chooses NTFS or exFAT and then
confirms permanent deletion. The operation deletes every password and all
data, removes the encryption configuration, repartitions, and reformats the
cartridge. There is no undo or data-recovery path.

For **Remove Basic Password Protection**, confirmation removes protection but
does not delete the stored user data; after completion the existing data is
normally accessible without authentication.

Removing the master credential through **View / Modify / Delete Existing
Passwords** invokes the same overall-protection removal paths. Removing AES
protection shows the destructive format flow; removing the Basic master shows
the non-data-deleting flow. Progress bars indicate the active stage and the
Password Management window refreshes afterward.

The reset-without-password facility is an erase/reuse mechanism only. The
manual explicitly treats lost-password recovery as impossible and outside the
product warranty.

Source coverage: Product Manual pp. 21-27.
