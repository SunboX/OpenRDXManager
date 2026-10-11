<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Advanced passwords and permissions

## Capability model

A protected cartridge supports up to eight configured passwords: one master
password and seven additional slots. Each added password has a unique display
name and these permissions:

- read access;
- optional write access;
- optional password create/change/delete authority.

The UI can add, list, change and delete credentials. Removing the master
password removes the overall protection mode (and for AES mode follows the
destructive encryption-removal/format path).

## Implementation overview

The Manager reads the cartridge credential table through RDX-specific security
command classes, renders its slots, and issues add/change/delete operations.
It enforces UI limits before sending: maximum eight passwords, unique names,
maximum password name 197 characters and maximum password 1024 characters as
shown in the executable.

Changing a password temporarily needs a free credential slot. Deleting the
credential that authenticated the current session ends that session. Failed
drive commands leave the table unchanged or trigger a refresh/error rather
than being treated as successful.

The permission meanings are proven at the UI/behavior level. The security
descriptor family and slot protocol are described below; some individual bit
positions remain unnamed and are not guessed.

## Implementation details

The Windows object keeps an eight-entry slot-presence/type/permission array and
an associated name/parameter record per slot. A global SECURITY PROTOCOL IN
reply supplies the occupied-slot mask; the Manager loops `0..7`, fetches each
slot's parameter descriptor, and separately obtains name data where supported.
It records which slot is currently authenticated and whether the slot is a
normal, master or automatic-drive credential.

For password verification it reads the slot generation/KDF parameters, runs
the two PBKDF2-HMAC-SHA-256 stages, builds a proof descriptor, submits it, then
refreshes the slot table. UI limits (eight slots, names/password length,
uniqueness) are host preconditions, not fields of the SCSI CDB.

## Protocol details

| Operation                      | Base command                 | Relevant fields                                  |
| ------------------------------ | ---------------------------- | ------------------------------------------------ |
| list slots/global state        | SECURITY PROTOCOL IN `0xA2`  | protocol `0x20`, selector, allocation `0x1000`   |
| get per-slot parameters/name   | SECURITY PROTOCOL IN `0xA2`  | slot-indexed selector                            |
| authenticate/add/change/delete | SECURITY PROTOCOL OUT `0xB5` | protocol `0x20`, selector, 32-bit payload length |
| confirm table/session          | SECURITY PROTOCOL IN `0xA2`  | refreshed descriptors                            |

The response parser recognizes descriptor IDs `0xC1` through `0xC5` and
bounded lengths (`0x48`, `0x2C`, or `0x08` for the observed structured types).
Occupied slots are represented as a bit mask, one bit per slot. Exact names
for every descriptor flag are unavailable because the Windows symbols are
stripped; the reference code does prove an eight-iteration slot loop and
permission/session fields.

## PDF-derived dialogs, permissions and limits

The **Advanced Passwords and Permissions** dialog offers four actions:

- **Add a Password**;
- **View / Modify / Delete Existing Passwords**;
- **Add an Automatic Drive Media Authentication Password**;
- **Delete Automatic Drive Media Authentication from RDX Drive**.

A cartridge has one master password plus at most seven additional or automatic
credentials. Adding a password always grants read access and separately offers
**Allow Write Access** and **Allow Password Create / Change / Deletion**. The
default display name can be changed before confirmation. The new credential is
effective as soon as the progress operation completes.

Password Management presents each credential as a row with change/delete
controls. A normal credential can be deleted without removing overall
protection. The master credential is not treated as a normal deletable slot:
its Remove action means remove AES encryption or Basic Password Protection,
with the different data-loss outcomes described in feature 09.

The Manager requires an authenticated session to open these controls. Closing
the Password Management window returns to Advanced Options; **Close** returns
to the Encryption tab. The documented password-strength scale and guidance in
feature 06 apply to every newly entered or changed credential.

If a drive was previously configured for automatic drive/media
authentication, the Encryption tab also exposes **Advanced Passwords and
Permissions** when an unencrypted cartridge is present so the drive-held
automatic credential can be removed.

Source coverage: Product Manual pp. 24-29; Windows 2.0.1 Release Notes p. 2.
