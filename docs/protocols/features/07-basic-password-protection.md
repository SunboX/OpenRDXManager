<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Basic password protection

## User-visible behavior

**Basic Password Protection** requires authentication before cartridge data
access but, unlike AES-256-XTS mode, does **not** encrypt the stored data. The
manual presents an explicit warning before enabling it because another system
that bypasses the RDX access-control path may still see plaintext data.

The setup flow selects Basic Password Protection, confirms the warning,
creates a master password and chooses whether reset/erase without a password
is permitted. The Encryption tab then reports `Password Protected`.

## Internal mechanism

The Manager uses cartridge password/configuration command classes shared with
the advanced password UI. It creates an access-control credential and changes
the cartridge's accessible session state; it does not establish the
`RDXEncrypt` XTS data path used by full-disk encryption.

Authentication success enables normal block I/O. Authentication failure keeps
data access disabled and is surfaced as a failed password/access operation.
The base security CDB is exact below; only the complete selector/descriptor
meaning table remains partially unnamed.

## Safety boundary

Basic protection is an access-control feature, not confidentiality against raw
media access. Removal normally requires a valid password. A permitted
passwordless reset clears configuration by erasing/resetting the cartridge and
can destroy data.

## Implementation details

The Manager enumerates eight possible credential slots, reads their presence,
type and permission metadata, and derives a password verifier using the same
two-stage PBKDF2-HMAC-SHA-256 path documented for AES mode. Basic protection
does not start the `RDXEncrypt`/Dokan XTS volume path; after successful
authentication the ordinary RDX block volume is exposed.

UI validation happens before the device transaction. The credential name,
permission choices, reset policy and password-derived proof are serialized as
security descriptors. Password bytes are processed by OpenSSL KDF calls;
reference code does not show a raw password copied directly into the CDB.

## Protocol details

The command layer is SECURITY PROTOCOL IN `0xA2` and SECURITY PROTOCOL OUT
`0xB5`, protocol byte `0x20`, 16-bit big-endian selector. IN normally requests
4096 bytes; OUT places its actual big-endian payload length in CDB bytes 6–9.

Typical transaction shape:

```text
A2/20: read global protection and occupied-slot descriptors
A2/20: read selected slot salts/iteration/generation parameters
host:  PBKDF2-HMAC-SHA-256 derivation and proof construction
B5/20: submit create/authenticate/configuration descriptor
A2/20: refresh protection/session/slot state
```

Observed reply descriptor types are `0xC1..0xC5`; the reference parser treats
length/type mismatch as failure. Exact values for every create/remove/reset
selector are still unnamed, so they are not guessed. The SCSI/host result
mapping is the same as feature 06.

## PDF-derived workflow, applicability and warnings

Basic Password Protection follows the same initial Encryption-tab selection,
master-password confirmation, strength display, reset-policy selection and
final confirmation as AES protection, but the NTFS/exFAT repartition step is
AES-specific. The manual displays an extra confirmation warning when Basic
Password Protection is selected because it controls access without encrypting
the underlying payload.

The Windows release notes state these qualifications:

- up to eight passwords can carry different read/write permissions;
- USB3 password protection requires dock firmware 0283 or later;
- protected RDX media can be used in RDX SATA III systems;
- firmware 0283 supports the drive-side feature in Fixed-Disk and
  Removable-Disk modes.

The same password-loss and reset distinction applies: reset clears protection
and can erase/reinitialize the medium; it does not reveal a forgotten password.
If reset was prohibited and every valid password is lost, the medium can
become unusable. The vendor excludes forgotten passwords from warranty.

Use the strength scale and recommendations recorded in feature 06. During a
protection operation the Encryption window is intentionally non-closable, and
the completed tab identifies the resulting state as password protected.

Source coverage: Product Manual pp. 16-19; Windows 2.0.1 Release Notes p. 2;
USB3 Firmware 0283 Release Notes p. 1.
