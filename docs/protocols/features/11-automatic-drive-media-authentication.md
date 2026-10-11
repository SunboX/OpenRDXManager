<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Automatic drive/media authentication

## Overview

For RDX SATA III, a drive can generate and retain an automatic-authentication
credential and add it to the inserted protected cartridge. On later insertion
in that associated drive, cartridge access is enabled without a user typing a
password. The user can allow or deny write access for that association.

A cartridge can hold associations for up to seven SATA III drives. A drive can
be associated with an unlimited number of cartridges because it reuses its
drive-held credential. USB and earlier SATA product variants are not described
as supporting this feature.

## Internal behavior

The manual and executable agree that the drive creates the key internally; the
Manager does not ask the user to invent it. The Manager instructs the drive to
create/read its automatic credential state and adds a corresponding credential
slot to the cartridge. Eject/reinsert is the documented verification step.

Deleting the drive's credential revokes automatic access for all cartridges
associated with that drive. Deleting only a cartridge association affects that
cartridge/drive relationship. Neither operation deletes the user's master
password; manual authentication remains possible.

The base on-wire security command and descriptor framework are exposed below;
the numeric selector assigned to every automatic-authentication sub-operation
is not symbolically named. The generated-key behavior, seven-association limit,
per-association write permission and deletion semantics are proven by bundled
manual and executable messages.

## Implementation details

The SATA III drive owns the automatically generated credential. The Manager
queries whether the drive has one, requests generation when needed, then adds
a corresponding automatic credential to an available non-master cartridge
slot. Because the master consumes one of eight total slots, at most seven drive
associations fit on a cartridge. The drive-side credential can be reused for
any number of cartridges.

Deleting the drive credential and deleting a cartridge slot are distinct code
paths. The first invalidates automatic authentication for every cartridge
paired to that drive; the second removes one association. The UI refreshes both
drive and cartridge state and requires eject/reinsert to test the autonomous
drive-side authentication event.

## Protocol details

Automatic-authentication state uses the same Tandberg security protocol:

```text
A2 20 ss ss 00 00 00 00 10 00 00 00   read drive/slot parameters
B5 20 ss ss 00 00 ll ll ll ll 00 00   generate/add/delete descriptor
```

The drive-generated secret is not transported as a user-entered password in
the UI. SECURITY PROTOCOL IN replies expose generation/slot parameters; OUT
submits association or deletion descriptors. On cartridge insertion, the
drive and cartridge security processors match the retained association and
establish the stored read or read/write permission without a host password
prompt. The exact secret format and all `ss` selector names remain proprietary
and are not inferred from UI strings.

Evidence anchors: `SCSecurityProtocolIn`/`Out` RTTI and CDB constructors in
the Windows implementation review plus the automatic-authentication UI/error strings.

## PDF-derived complete association lifecycle

This feature is intended for unattended backup/data exchange and for data or
system recovery without RDX Manager running. The SATA III drive generates the
key internally; no operator password is needed when a paired cartridge is
inserted in that drive. Off-site or in another unconfigured drive, the
cartridge remains AES encrypted/password protected and can still be opened
with one of its assigned user passwords.

The documented add flow is:

1. Choose **Add Drive's Automatic Authentication Password to Cartridge**.
2. Leave **Allow Write Access** selected for read/write use, or clear it to
   make automatic access read-only.
3. Confirm and wait for the add progress operation.
4. Observe that Add becomes grayed out and Delete becomes active.
5. Eject and reinsert the cartridge to verify automatic authentication; the
   encryption status then reports auto-decrypted access.

Write permission cannot be upgraded in place. To re-enable writes for an
association created read-only, delete/disable the current automatic
authentication and add it again with **Allow Write Access** selected.

An encrypted cartridge can contain automatic credentials for as many as seven
different SATA III drives. Each SATA III drive can automatically authenticate
an unlimited number of cartridges. Deleting the drive's automatic credential
causes every cartridge paired to that drive to require its normal password on
future insertion; it does not remove cartridge protection or erase data.

With an unencrypted cartridge inserted, Advanced Options can still delete the
drive's automatic-decryption credential. After deletion, Add becomes active
and Delete becomes grayed out.

Source coverage: Product Manual pp. 27-30.
