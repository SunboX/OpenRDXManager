<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Full-disk AES-256-XTS encryption

## User-visible behavior

The Encryption tab can configure **Full Disk AES 256 XTS Encryption** for a
cartridge. The user chooses a master password, optional reset-without-password
policy, and a filesystem format. Enabling or removing encryption repartitions/
formats the cartridge and therefore destroys its prior contents.

With protection active, the status is `AES 256 Encrypted`; access can be
disabled and later enabled by authenticating. Password loss can make the
cartridge unusable unless reset/erase without a password was allowed.

## Implementation overview

The Windows installation bundles:

- `RDXEncrypt`, RDXmon and Dokan components for the protected volume path;
- `libcrypto-1_1.dll`, providing cryptographic primitives;
- SCSI cartridge security/password command classes used to store and manage
  protection metadata and authentication state.

Executable strings explicitly say `Setup XTS AES 256 encryption based on
password` and distinguish software-encryption read-only/unsupported states.
This shows a combined host volume layer and device/cartridge control path. The
password derivation is recoverable as described below; the on-media XTS sector
metadata/layout and exact key-wrapping descriptor semantics remain unresolved.

## Success and failure

Success requires protection configuration, reformat completion and subsequent
authenticated volume availability. Common failures are unsupported drive,
write-protected media, lost access during reformat, or format failure. Removal
permanently deletes encrypted contents because the protected layout/key state
is removed and the cartridge is formatted.

Advanced credential slots and permissions are documented separately in
[10-advanced-passwords-and-permissions.md](10-advanced-passwords-and-permissions.md).

## Implementation details

The Windows security library performs a two-stage PBKDF2-HMAC-SHA-256 flow.
The first call derives 64 bytes from the user's password with a 32-byte
drive-supplied salt and iteration count. A second PBKDF2-HMAC-SHA-256 call
derives another 64 bytes from that result using a second 32-byte parameter set
and iteration count. The derived material is then used to build/verify the
security descriptors exchanged with the RDX security offload processor.

The executable calls OpenSSL `EVP_sha256` and `PKCS5_PBKDF2_HMAC` directly; no
plain password write is visible in the reference command path. `RDXEncrypt`
and Dokan expose the authenticated/decrypted Windows volume. The Manager
checks Dokan installation through Qt Remote Objects before enabling software
encryption operations. Partition/format is coordinated after protection
metadata changes.

## Protocol details

Protection uses standard 12-byte SCSI security commands with Tandberg protocol
ID `0x20`:

```text
SECURITY PROTOCOL IN:
A2 20 ss ss 00 00 00 00 10 00 00 00

SECURITY PROTOCOL OUT:
B5 20 ss ss 00 00 ll ll ll ll 00 00
```

`ss ss` is the big-endian protocol-specific selector. IN uses a default
allocation length of `0x00001000` (4096 bytes), data-in. OUT carries a
big-endian 32-bit transfer length at bytes 6–9, data-out. Observed protocol-IN
selectors include `0x0020`, `0x0021` and slot-indexed selectors. The descriptor
parser recognizes types `0xC1` through `0xC5`; observed serialized lengths are
`0x48` for `0xC2/0xC4`, `0x2C` for `0xC3`, and `0x08` for `0xC5`.

The precise UI-operation-to-every-selector/descriptor mapping is not fully
named because the current Windows binary is stripped. SCSI GOOD plus valid
descriptor parsing is success; CHECK CONDITION or malformed/short descriptors
fail the operation. Transport result `3` means IOCTL/transfer failure and `4`
means SCSI status/sense failure.

Evidence anchors: Windows functions around `0x00462510`
(`SCSecurityProtocolIn`), `0x00469FC0` (`SCSecurityProtocolOut`) and
`0x00455AD0` (PBKDF2 verification path).

## PDF-derived prerequisites and complete setup workflow

The Windows release notes qualify volume password protection for RDX QuikStor
USB3 systems running dock firmware `0283` or later and state that protected
media is compatible with RDX SATA III systems. Firmware 0283 added the USB3
drive-side password-protection support in both Removable-Disk and Fixed-Disk
modes. This is an applicability requirement, not a change to the host CDB
layout.

The manual's AES setup sequence is:

1. Open the Encryption tab and choose **Enable Cartridge Encryption/Password
   Protection**.
2. Select **AES 256 XTS Encryption**.
3. Enter and confirm the master password and review its strength indicator.
4. Choose the cartridge reset/erase policy.
5. Select NTFS or exFAT, confirm the destructive operation, and wait for the
   protection/partition/format sequence to finish.
6. Verify that the Encryption tab reports AES protection after the progress
   bar completes.

The UI locks the Encryption window while an operation is in progress. Windows
release 0.1.0.28 explicitly fixed the ability to close that window during an
operation.

### Reset/erase and password-loss boundary

The checkbox is named **Allow Cartridge Reset and Erase All Encryption
Configuration Without a Password**. Allowing reset makes reuse possible by
erasing protection configuration and all encrypted contents; it never recovers
the original data. The manual also warns that a permitted erase can be
initiated using any cartridge password, including a read-only credential.
Disallowing reset prevents a person with physical access from clearing and
reusing the cartridge, but loss of all passwords then leaves it unusable.

The vendor states that data-recovery services are excluded and impossible for
lost AES credentials and that forgotten passwords are not covered by the
product warranty. Removal or reset has no undo path because the passwords/key
state that made the sectors readable are destroyed.

### Password-strength guidance

The strength indicator reports `Poor`, `Weak`, `Better`, `Good`, or `Very
Good`. The manual gives two approaches: at least 12 characters with mixed case,
numbers and symbols and no dictionary words/obvious substitutions; or, for a
modern passphrase, at least six unrelated words with random capitalization and
interspersed numbers/symbols.

Source coverage: Product Manual pp. 16-24; Windows 2.0.1 Release Notes p. 2;
USB3 Firmware 0283 Release Notes p. 1.
