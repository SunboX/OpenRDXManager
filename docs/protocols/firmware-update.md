<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Firmware update protocol

protocol review report for the installers and firmware files in this
folder. Analysis date: 2026-08-25.

## Result in one paragraph

RDX Manager does not invoke a TI/JTAG/DFU/serial firmware utility. It sends
ordinary 10-byte SCSI `WRITE BUFFER` commands to the RDX mass-storage device.
For a USB 3/SATA 3 TAD `.BIN`, it sends the complete container in 4096-byte
mode-`0x04` chunks and follows it with a zero-length mode-`0x05` command. The
private TUSB9261 firmware proves what happens below that host protocol: the
drive parses and authenticates the container as a stream, extracts only the TI
boot image, erases sixteen 4-KiB M25PE20 sectors (`0x00000..0x0FFFF`), and
programs it with SPI Write Enable (`0x06`), Sector Erase (`0x20`), and Page
Program (`0x02`). It withholds the first four boot bytes until the stream,
checksum, and public-key signature checks succeed, writes those bytes last,
then mode `0x05` transitions to the finish/reset path. The 62,110-byte 0283 file
produces exactly 17 host CDBs: 16 data commands plus one final command. Windows
uses native SCSI pass-through against `\\.\PhysicalDriveN`; macOS uses a
privileged XPC helper and the bundled `RDXMonitor.kext` `/dev/RDXDiskN`
interface.

## Scope, evidence, and confidence

This report is based on static analysis of the exact files in this directory:

- RDX Manager 2.0.1.50 and 2.0.1.54 Windows installers
- RDX Manager for Mac 0.1.0.1
- `original-inputs/RDX2E__STD__F-0283.bin` and its ZIP container
- the bundled help and supplied vendor manuals/release notes
- Windows and macOS implementation references
- the private 256-KiB M25PE20 flash read, symbol-bearing TUSB9261 ELF, retained
  firmware workspace, and drive firmware reference material under the parent
  `OpenRDX` folder

Confidence labels used below:

- **Confirmed**: directly represented in code, bytes, installer resources, or
  vendor documentation.
- **Strong inference**: several independent code/byte observations agree, but
  a standard-library reproduction or hardware trace has not completed the
  proof.
- **Unknown**: not recoverable from these host-side installers/files.

The exact host protocol, byte fields, retry behavior, return handling, OS
transport, drive command handler, flash erase/program sequence, and updater to
flash byte mapping are supported by the retained implementation references.
The drive C files are reference material, not original vendor source; compare
runtime addresses and original image bytes when names or types matter. These
offline checks do not establish hardware verification.

## Safety warning

SCSI WRITE BUFFER is destructive firmware-update functionality. Do not replay
these commands against an arbitrary disk. Vendor instructions require that the
RDX cartridge be ejected and power remain on for the entire update. A wrong
target, interrupted power, malformed image, or bypassing product checks can
brick a drive. The saved analysis scripts are offline extractors/analyzers and
intentionally do not send live commands.

## Complete update sequence

The normal USB 3/SATA 3 path is the class named
`Test_DownloadFirmwareTAD`/`SCWbRDXDownloadMicrocodeTAD` in the binaries.

1. The UI requires no cartridge/media in the drive. It asks the user for a
   drive-appropriate image: `.BIN` for USB 3/SATA 3, `.BIP` for USB 2/SATA 1.
2. The file is opened and its TAD container is parsed. RDX Manager checks that
   it is structurally acceptable and that its embedded product metadata matches
   the selected RDX product.
3. A SCSI WRITE BUFFER command object is created with opcode `0x3B`, buffer ID
   `0`, mode `4`, data-out direction, offset `0`, and a 4096-byte buffer.
4. For every file chunk, Manager copies up to 4096 bytes into the command data
   buffer, sets mode `4`, the current absolute byte offset, and the actual chunk
   length, then sends the command.
5. During mode-4 processing, the drive incrementally parses the container and
   programs the embedded TI boot region. On the final data chunk it validates
   the container checksum and cryptographic signature, then writes the four
   withheld boot-header bytes at flash address zero.
6. If every data command succeeds, Manager sends mode `5`, buffer ID `0`,
   offset equal to the full file size, and transfer length `0`. The drive
   requires the completed state plus zero length, clears the update parser, and
   enters its finish/reset path.
7. On success it closes/reloads the device and waits for it to reconnect,
   polling for up to 15 iterations at roughly one second per iteration.
8. If an ordinary transfer fails, the whole download is retried once from byte
   zero. A second failure ends with internal error `0x4F`.

Equivalent algorithm outline:

```text
validate_tad_container(file, selected_drive)

attempts_remaining = 1
repeat:
    offset = 0
    command = WRITE_BUFFER(opcode=0x3B, buffer_id=0,
                           mode=4, offset=0, length=0x1000)

    while (chunk = read(file, up_to=0x1000)):
        command.mode   = 4
        command.offset = offset
        command.length = len(chunk)
        command.data   = chunk
        # The drive parses/checks/programs synchronously during these sends.
        require_scsi_success(send(command))
        offset += len(chunk)

    command.mode   = 5               # finish/reset; no payload
    command.offset = offset
    command.length = 0
    require_scsi_success(send(command))

    if success:
        close_or_reload_device()
        wait_for_reconnect(15)
        return success

    if attempts_remaining == 0:
        return error_0x4f
    rewind_file_and_rebuild_command()
    attempts_remaining -= 1
```

### Exact WRITE BUFFER CDB layout

The CDB is always ten bytes:

| Byte(s) | Value/encoding                            | Meaning                                   |
| ------- | ----------------------------------------- | ----------------------------------------- |
| 0       | `0x3B`                                    | SCSI WRITE BUFFER opcode                  |
| 1       | preserved high nibble, mode in low nibble | `0x04` for data; `0x05` for final step    |
| 2       | `0x00`                                    | buffer ID                                 |
| 3..5    | 24-bit big-endian                         | absolute byte offset in the firmware file |
| 6..8    | 24-bit big-endian                         | data-out transfer length                  |
| 9       | `0x00`                                    | control                                   |

The Manager's builder changes the low mode nibble while preserving the high
nibble. The drive handler at `0x08004884` actually decodes the field as
`CDB[1] & 0x1F`; for normal mode `4`/`5` commands both descriptions yield the
same value.

Formula:

```text
3B mode 00 off[23:16] off[15:8] off[7:0]
           len[23:16] len[15:8] len[7:0] 00
```

There is no response payload. Success means SCSI status GOOD. Failure is
reported as transport failure or SCSI CHECK CONDITION with sense data.

### Every command for firmware 0283

The supplied image is 62,110 bytes (`0x00F29E`), so Manager sends:

|   # | Purpose    |     Offset |     Length | Exact CDB                       |
| --: | ---------- | ---------: | ---------: | ------------------------------- |
|   1 | data       | `0x000000` | `0x001000` | `3b 04 00 00 00 00 00 10 00 00` |
|   2 | data       | `0x001000` | `0x001000` | `3b 04 00 00 10 00 00 10 00 00` |
|   3 | data       | `0x002000` | `0x001000` | `3b 04 00 00 20 00 00 10 00 00` |
|   4 | data       | `0x003000` | `0x001000` | `3b 04 00 00 30 00 00 10 00 00` |
|   5 | data       | `0x004000` | `0x001000` | `3b 04 00 00 40 00 00 10 00 00` |
|   6 | data       | `0x005000` | `0x001000` | `3b 04 00 00 50 00 00 10 00 00` |
|   7 | data       | `0x006000` | `0x001000` | `3b 04 00 00 60 00 00 10 00 00` |
|   8 | data       | `0x007000` | `0x001000` | `3b 04 00 00 70 00 00 10 00 00` |
|   9 | data       | `0x008000` | `0x001000` | `3b 04 00 00 80 00 00 10 00 00` |
|  10 | data       | `0x009000` | `0x001000` | `3b 04 00 00 90 00 00 10 00 00` |
|  11 | data       | `0x00A000` | `0x001000` | `3b 04 00 00 a0 00 00 10 00 00` |
|  12 | data       | `0x00B000` | `0x001000` | `3b 04 00 00 b0 00 00 10 00 00` |
|  13 | data       | `0x00C000` | `0x001000` | `3b 04 00 00 c0 00 00 10 00 00` |
|  14 | data       | `0x00D000` | `0x001000` | `3b 04 00 00 d0 00 00 10 00 00` |
|  15 | data       | `0x00E000` | `0x001000` | `3b 04 00 00 e0 00 00 10 00 00` |
|  16 | final data | `0x00F000` | `0x00029E` | `3b 04 00 00 f0 00 00 02 9e 00` |
|  17 | finalize   | `0x00F29E` |        `0` | `3b 05 00 00 f2 9e 00 00 00 00` |

A machine-readable command listing can be regenerated for another `.BIN`
using the optional local tool `analysis/scripts/analyze_firmware.py`.

## Return values and expected failures

The updater's command layer normalizes results as follows:

| Result | Meaning                                           | Update behavior                    |
| -----: | ------------------------------------------------- | ---------------------------------- |
|    `0` | SCSI command successful/GOOD                      | Continue; after mode 5, reconnect  |
|    `3` | OS pass-through/ioctl failure or invalid transfer | Download attempt fails             |
|    `4` | CHECK CONDITION/sense returned                    | Inspect sense; normally fail/retry |

WRITE BUFFER commands are configured to tolerate/retry UNIT ATTENTION. The
Mac command constructor explicitly sets five UNIT ATTENTION retries; the
Windows pass-through loop implements the corresponding retry behavior.

The most important mapped sense value is:

| Sense key |    ASC |   ASCQ | Meaning                                                              | Manager result                                                             |
| --------: | -----: | -----: | -------------------------------------------------------------------- | -------------------------------------------------------------------------- |
|    `0x07` | `0x74` | `0x08` | DATA PROTECT / SECURITY ERROR / DIGITAL SIGNATURE VALIDATION FAILURE | mapper index `0x2D`; internal error `0x63`; UI: `Firmware Signature Error` |

The Windows machine code checks mapper result `0x2D` after both a mode-4 data
send and the mode-5 final send, adds `0x36`, and throws error `0x63`. The log
string is `Download command failed, DIGITAL_SIGNATURE_VALIDATION_FAILURE`.
This is direct evidence that cryptographic acceptance is enforced by the
drive, not by OpenSSL in the host application.

Other confirmed update-level errors:

| Internal code | Meaning                                                           |
| ------------: | ----------------------------------------------------------------- |
|        `0x4E` | Error reading firmware file                                       |
|        `0x4F` | Download command failed after the single full retry               |
|        `0x50` | Device did not reconnect after firmware download (UI/error table) |
|        `0x63` | Firmware digital-signature validation failed                      |

During the reconnect check, TEST UNIT READY result `4` is accepted as evidence
that the device path is present. The updater then closes the type-1 handle,
opens device type 3, closes it, and reopens type 1. If that chain is not ready,
it closes and polls again. The limit passed by the TAD updater is `15`.

## Windows transport

Confirmed behavior in RDX Manager 2.0.1.54:

- The physical target is formatted as `\\.\PhysicalDrive%d` and opened with
  `CreateFileW`, read/write access, and read/write sharing.
- Data-bearing firmware commands go through `DeviceIoControl` control code
  `0x4D014`, which is `IOCTL_SCSI_PASS_THROUGH_DIRECT`.
- The direct structure has a `0x2C`-byte SCSI pass-through header, CDB length
  10 for WRITE BUFFER, sense length `0x12`, a data pointer, timeout, and a
  separate sense/result buffer.
- The alternate no-data/buffered path uses control code `0x4D004`,
  `IOCTL_SCSI_PASS_THROUGH`, with a `0x250`-byte combined buffer. This is the
  applicable path for commands without an external transfer buffer, including
  the zero-length final command depending on the command dispatch branch.
- Returned SCSI status zero is success. Non-zero SCSI status is converted to
  result `4` and the fixed-format sense bytes are copied/mapped. OS ioctl or
  transfer-length failure becomes result `3`.

The firmware algorithm is in `RDXManager.exe`; there is no separately bundled
FlashBurner/flasher executable. `RdxCmdLine.exe` contains the same host-tools
library vocabulary but is not launched as a separate flasher by the GUI path.

## macOS transport

The old Mac package needs extra plumbing because the GUI does not issue the
private driver ioctl itself:

1. `RdxManager` builds a Linux-style `sg_io_hdr` in memory. It sets interface
   ID `S` (`0x53`), direction `-2` for data-out (`-3` for data-in and `-1` for
   no data), CDB pointer/length, data pointer/length, sense pointer, and timeout
   in milliseconds.
2. It sends the package over XPC to the bundled privileged helper
   `com.tandbergdata.rdx.HelperTool`.
3. The helper checks an Authorization Services right for the requested
   command. The send right is `com.tandbergdata.rdx.sendScsiCommand` and is
   configured as an administrator-authorized operation.
4. The helper opens `/dev/RDXDisk%ld`, exposed by the bundled
   `RDXMonitor.kext`, and calls ioctl `0xC0086102` with a pointer to the
   reconstructed `sg_io_hdr`.
5. The updated status, residual length, sense, and data are repackaged into the
   XPC reply. The Manager maps ioctl failure to `3`, sense/check failure to `4`,
   and clean completion to `0`.

Related private driver operations visible in the helper are `0xC0086101`
(driver/kext version), `0xC0086102` (SCSI command), and `0xC0086104`
(device-path/mount/eject-related query). The kext matches SCSI peripheral type
0 RDX devices from several vendor/product ID combinations.

## Firmware container 0283

Confirmed file facts:

| Property                   | Value                                                              |
| -------------------------- | ------------------------------------------------------------------ |
| Filename                   | `original-inputs/RDX2E__STD__F-0283.bin`                           |
| Size                       | 62,110 bytes (`0xF29E`)                                            |
| SHA-256                    | `73d528801aefc032d3a53637b035f65d72809151b2f127c6b2050e9bacc76f3b` |
| BE32 at `0x00`             | `0x0000F27E` = file size minus `0x20`                              |
| BE32 at `0x04`             | `0x0000F29E` = exact file size                                     |
| ASCII at `0x0C`            | `0283`                                                             |
| Record count at `0x20`     | `1`                                                                |
| First record type          | `1`                                                                |
| Parsed target/load address | `0x00004000`                                                       |
| Product/version metadata   | includes `0283`, `S3`, `R2eF`, and Tandberg copyright/build text   |

The file inside `original-inputs/RDX_USB3_external_firmware-0283.zip` is byte-for-byte
identical to the standalone file.

### Host-side parser behavior

The 2.0.1.54 parser performs these confirmed operations:

1. Read two big-endian 32-bit lengths.
2. If the second minus the first is `0x20`, seek to offset `0x20`; otherwise
   parse from offset `0`.
3. Read a big-endian record count and reject counts greater than 100.
4. Scan records for record type `1`.
5. Read a 28-byte record header and enforce its additive/boundary consistency
   relation.
6. Recover target/load address `0x4000` for this image.
7. Follow the record displacement to file offset `0x60`, read `0xA0` bytes of
   product metadata, and extract version components `02` and `83`.
8. Reject malformed parser outcomes and an identity left as `NULL`; the UI
   also compares parsed product information to the selected drive.

File open/seek failure is reported by the file object as `0x13`; rejected
format/parser results become validation error `0x10` in the host layer.

### Checksums, signature, and exact regions

The vendor release notes state that firmware 0278 introduced digitally signed
firmware and that older unsigned releases cannot be loaded after upgrading.
0283 is later and the Manager/drive has the explicit `07/74/08` signature-fail
path described above.

Bytes `0x108..0x187` are the confirmed 128-byte RSA signature. Drive code contains the
standard SHA-256 initial state constants (`6A09E667`, `BB67AE85`, ...), its
64-byte compression/finalization path, and a 32-byte digest comparison. It
converts the signature to big-integer words and applies the embedded 1024-bit
RSA public key. The public exponent is `65537`; the modulus is stored
little-endian at runtime `0x0800E7CC`, referenced by the key structure at
`0x0800E9E0`.

The saved verifier reproduces the operation independently. The decoded block
is exactly:

```text
00 01 [74 bytes of FF] 00
30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
ed6bb78448c039d75000264bdd309052e7ff6c88db1f109e7ef3d6a94a76be1f
```

That is valid RSASSA-PKCS1-v1_5 with SHA-256. The digest equals SHA-256 of
exactly `.BIN[0x18C:0xF29A]`, the complete 61,710-byte TI formatted boot region.
`analysis/private-firmware/signature/signature-verification.json` records
`signature_valid: true`. The host does not perform this operation; the drive
does.

The saved slices provide an exact byte map of this 0283 container:

| Slice                                     |          Offsets | Status                                                    |
| ----------------------------------------- | ---------------: | --------------------------------------------------------- |
| `outer_header.bin`                        |   `0x000..0x01F` | confirmed outer header                                    |
| `record_and_product_metadata.bin`         |   `0x020..0x107` | confirmed parser/metadata area                            |
| `rsa1024_pkcs1_v1_5_sha256_signature.bin` |   `0x108..0x187` | confirmed RSA-1024 signature                              |
| `metadata_rolling_check.bin`              |   `0x188..0x18B` | confirmed big-endian metadata rolling check `D2496C6F`    |
| `tusb9261_boot_formatted_region.bin`      |  `0x18C..0xF299` | exact match to flash `0x00000..0x0F10D`                   |
| `tusb9261_arm_payload.bin`                |  `0x199..0xF298` | exact ARM payload, runtime `0x08000000`                   |
| `container_trailer.bin`                   | `0xF29A..0xF29D` | confirmed big-endian boot-region rolling check `6FBA6B80` |

Byte `0xF299` (`59`) is now identified: it is the valid additive checksum byte
of the TI type-2 firmware record and lives inside the exact formatted boot
region. The two outer checks use the exact drive routine at `0x0800A840`, with
polynomial `0x04C11DB7` but a nonstandard post-shift conditional. Starting at
`0xFFFFFFFF`, bytes `0x000..0x187` produce stored value `D2496C6F`; feeding that
stored value produces residue zero. Starting at zero, the complete boot region
`0x18C..0xF299` produces the final stored value `6FBA6B80`. Both are regenerated
in `firmware-analysis.json`.

## Drive-side implementation: TUSB9261 to M25PE20

This section correlates the Manager protocol with the private firmware. It is
not inferred merely from a similar TI example: the complete boot region inside
the updater is byte-identical to the physical flash read.

### Controller, image, and flash layout

| Property                           | Confirmed value                                                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Controller                         | TI TUSB9261, Cortex-M3, Thumb-2                                                                                             |
| External firmware flash            | M25PE20, 2 Mbit / 256 KiB SPI NOR                                                                                           |
| Raw flash SHA-256                  | `058d1f0b3a22f7833106cf9e2a952ced9d8090802649e728ed5b80032c6cf5f9`                                                          |
| Formatted boot-region size/SHA-256 | `0xF10E` / `ed6bb78448c039d75000264bdd309052e7ff6c88db1f109e7ef3d6a94a76be1f`                                               |
| ARM payload size/SHA-256           | `0xF100` / `4854e7c7b61c286c2a969adb9670151a627c6c079aa71f98073bfb1bf8ff9f21`                                               |
| Runtime base                       | `0x08000000`                                                                                                                |
| Initial MSP / reset handler        | `0x0800FEF0` / `0x0800B944` (stored Thumb vector `0x0800B945`)                                                              |
| Embedded identity                  | `TANDBERG` / `RDX`, USB `1A5A:0005`, `bcdDevice 0283`                                                                       |
| Active USB interface               | one Mass Storage Bulk-Only Transport interface; endpoints `0x83` IN and `0x03` OUT; no active firmware-update HID interface |
| Build timestamp                    | `Oct 11 2019 12:04:15`                                                                                                      |

Physical flash map:

|        Flash range |    Length | Meaning/update behavior                                                                |
| -----------------: | --------: | -------------------------------------------------------------------------------------- |
| `0x00000..0x00001` |         2 | TI firmware identifier `0x9260`; withheld and written last as part of first four bytes |
| `0x00002..0x00007` |         6 | empty descriptor record and checksum                                                   |
| `0x00008..0x0000C` |         5 | TI type-2 firmware-record header, payload length `0xF100`                              |
| `0x0000D..0x0F10C` |  `0xF100` | ARM firmware payload                                                                   |
|          `0x0F10D` |         1 | valid additive record checksum `0x59`                                                  |
| `0x10000..0x3DFFF` | `0x2E000` | outside the updater erase/program range                                                |
| `0x3E000..0x3E0FF` |       256 | checksum-protected version-6 unit/manufacturing/USB identity record; preserved         |
| `0x3E100..0x3EFFF` |   `0xF00` | erased remainder of its 4-KiB sector in the captured unit                              |
| `0x3F000..0x3F03F` |        64 | checksum-protected Load Count and saved MODE PAGE `0x34` state; preserved              |
|          `0x3F190` |         1 | erased recovery/bootstrap value for MODE PAGE `0x34` in the captured unit              |
| `0x3FC00..0x3FC3F` |        64 | erased fallback state record in the captured unit                                      |

The exact upper-flash checksums, field names, defaults, factory READ/WRITE
BUFFER interface and erase-sector interactions are documented in
[`high-flash-configuration.md`](high-flash-configuration.md).

Exact container-to-flash mapping:

```text
RDX .BIN 0x00000..0x0018B   outer update metadata/signature
RDX .BIN 0x0018C..0x0F299   == M25PE20 0x00000..0x0F10D
RDX .BIN 0x00199..0x0F298   == ARM image loaded at 0x08000000
RDX .BIN 0x0F29A..0x0F29D   boot-region rolling check 6F BA 6B 80
```

The equality is checked and recorded in
`analysis/private-firmware/correlation/correlation.json`; both comparisons are
`byte_for_byte_match: true`.

### Drive command dispatch and field decoding

The drive's SCSI descriptor at runtime `0x0800E180` begins with these six
little-endian words:

```text
0000003B 00000002 00000000 08004885 00000008 0800E320
```

This binds opcode `0x3B` to Thumb entry `0x08004885` (executable address
`0x08004884`). Some other descriptor fields remain deliberately unnamed; in
particular, the word `8` must not be mistaken for the 10-byte CDB length without
additional table-structure proof.

The handler at `0x08004884` performs:

```text
buffer_id = CDB[2]
mode      = CDB[1] & 0x1f
offset    = BE24(CDB[3..5])
length    = BE24(CDB[6..8])

mode 4  -> streamed_update(data, offset, length, final_flag=0)
mode 5  -> streamed_update(data, offset, length, final_flag=1)
mode 2  -> private buffer-ID operations (0x80/0x82 authorization path)
mode 15 -> separate accepted special path, unused by normal Manager update
other   -> internal command status 8 (invalid)
```

It rejects a transfer longer than the allocated command resource, reports
internal status `0x1F` on allocation failure, and always releases the command
buffer on exit. The SCSI layer turns a zero internal result into GOOD and maps
failures to CHECK CONDITION/sense as appropriate.

### Streaming parser and validation state machine

Mode 4/5 enters the wrapper at `0x0800A0E8` and parser/coordinator at
`0x08000AEC`:

1. Offset zero clears a persistent `0x198`-byte update state and marks an
   update active.
2. The first transfer must contain at least `0x20` bytes. The parser reads the
   big-endian outer lengths/record metadata, validates bounds and additive
   relations, and locates the signed record and embedded TI boot region.
3. Every later call must continue at the expected absolute file offset; chunks
   cannot be silently reordered or skipped.
4. It maintains the two outer rolling checks plus a SHA-256 state while
   forwarding only the TI boot-region bytes to the flash writer. The outer
   Manager metadata and final four-byte trailer are not written verbatim to
   flash.
5. When the first boot bytes arrive, it saves bytes `0..3`, erases the sixteen
   boot sectors, and starts programming at flash address `4`.
6. Near the end it compares stored rolling value `6FBA6B80`, finalizes SHA-256,
   and verifies RSA-1024/PKCS#1 v1.5 signature `0x108..0x187` over the complete
   TI boot region. Invalid format/check states use internal codes
   including `0x20`, `0x2C`, and `0x2D`; these are drive-local values and must
   not be confused with Manager's host error numbers.
7. Only after all checks succeed does `0x0800B648` program the saved four bytes
   at address zero. With a mode-4 last chunk the parser enters completed state 2. A subsequent mode-5 call with the expected final offset and zero length
   clears the parser and invokes the finish/reset transition at `0x0800CFA0`.

The signature-failure sense table is independently present in the drive image:
bytes at runtime `0x0800E73B` contain `07 74 08`, exactly the triple that
Manager translates to `Firmware Signature Error`.

### Exact SPI erase/program operations

The first flash write goes through `0x0800A53C`. It copies the first four TI
boot bytes aside and invokes `0x0800C7C8`, which loops 16 times with addresses
`sector_index << 12`. Each sector operation at `0x0800A504` sends:

```text
0x06  WRITE ENABLE
0x20  SECTOR ERASE at 0x00000, 0x01000, ... 0x0F000
delay/poll path
```

Programming at `0x08007BFC` splits writes at 256-byte page boundaries and, for
each piece, sends:

```text
0x06  WRITE ENABLE
0x02  PAGE PROGRAM(address, data, length <= bytes remaining in page)
delay/poll path
```

Finally `0x0800B648` invokes the same page-program loop for length four at
address zero. Thus a signature is checked late, after most flash writes, but
the TI boot identifier/header remains invalid until authenticated completion.
The erased range ends at `0x0FFFF`, so manufacturing and state sectors are not
touched by this update implementation.

## Legacy `.BIP` path and internal header-check commands

The manual distinguishes legacy USB 2/SATA 1 `.BIP` from USB 3/SATA 3 `.BIN`.
The binary contains a separate `SCWbRDXDownloadMicrocode` path for the legacy
format:

- WRITE BUFFER mode `6`
- buffer ID `0`
- 256-byte (`0x100`) chunks
- advancing absolute offset
- final mode `7`

This is confirmed class behavior, but no `.BIP` file was supplied, so no exact
legacy command transcript can be generated here.

There is also a non-default, internal/test option named `disableHeaderCheck`.
It is not part of the normal GUI update and should not be used. When enabled,
it first obtains the standard inquiry serial number and sends:

1. WRITE BUFFER mode `2`, buffer ID `0x80`, offset `0`, length `10`:
   `3b 02 80 00 00 00 00 00 0a 00`.
   Payload bytes 0 and 1 are zero. Payload bytes 2..9 are serial-number
   characters 2..9 XOR `55 aa 25 46 04 c1 1d b7`.
2. WRITE BUFFER mode `2`, buffer ID `0x82`, offset `0x020FF8`, length `2`:
   `3b 02 82 02 0f f8 00 00 02 00`, with payload `00 00`.

The values `0x80` and `0x82` are buffer IDs, not WRITE BUFFER modes. Drive code
at `0x080077CC` confirms the complete 10-byte serial/XOR test for ID `0x80` and
sets a global authorization flag only on success. ID `0x82` is rejected unless
that flag is set, then calls the internal routine at `0x0800CD6C`. The final
configuration bit/word changed by that routine is not yet semantically named;
"disable header check" comes from the Manager class/log path.

## What is bundled

### Windows 2.0.1.54

The outer ZIP contains a Windows Qt Installer Framework executable. The
embedded IFW reports version 3.0.6 built with Qt 5.9.5 and contains two
components:

| Component                     | Notable payload                                                                                                                                                                                                                  |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `com.tandbergdata.RdxManager` | `RDXManager.exe`, `RdxCmdLine.exe`, Qt 5 GUI/Help/Network/SQL/RemoteObjects libraries, translations, Qt Assistant/help, OpenGL software libraries, Dokan library, OpenSSL `libcrypto-1_1`/`libssl-1_1`, eject/service installers |
| `com.microsoft.vcredist.x86`  | `vc_redist.x86.exe`, version `14.16.27027.1`                                                                                                                                                                                     |

The Eject subcomponent contains `RDXmon.exe`, Qt Core/Network/RemoteObjects,
Dokan, OpenSSL, event DLL, registry/setup utilities, and scripts. These support
monitoring/eject/OS integration; firmware transfer itself is inside the Manager
host-tools code.

Windows 2.0.1.50 has the same component structure with 2.0.1.50 Manager/Eject
payloads. The supplied firmware 0283 is separate: neither Manager installer
contains a `.BIN` or `.BIP` image.

### macOS 0.1.0.1

The Qt IFW data contains:

- `RdxManager.app` (x86-64, linked against Qt 5.7 frameworks)
- Qt Assistant and the RDX help collection
- `com.tandbergdata.rdx.HelperTool`
- `RDXMonitor.kext`
- `RDXMon` launch daemon and `com.tandbergdata.RDXmon.plist`
- driver reload/install support script

Again, no firmware image is embedded.

### Integrity

All 12 extracted Qt IFW `.7z` payloads match their embedded SHA-1 sidecars.
Original input SHA-256 values are saved in
`analysis/extracted/inventory/SHA256SUMS.txt`; detailed embedded verification is
in `analysis/extracted/inventory/EMBEDDED_SHA1_VERIFICATION.txt`.

## Tools used internally by the vendor versus tools used for this analysis

Vendor update stack:

- RDX Manager's statically linked/shared host-tools classes
- Windows `CreateFileW` + SCSI pass-through IOCTLs
- macOS XPC privileged helper + Authorization Services + RDXMonitor private
  SCSI ioctl
- standard SCSI WRITE BUFFER and TEST UNIT READY commands
- Qt for the UI/installer and platform integration

Not used by this update path: TI FlashBurner, JTAG, UART, HID firmware loader,
USB DFU, a vendor serial protocol, or a separately launched flashing program.

## Reference material and reproducibility

The reference set combines vendor documentation, installer resources, firmware
images, implementation references, and deterministic offline checks. An
implementation reference is not original vendor source and does not establish
hardware validation. Addresses, hashes, protocol bytes, and unresolved limits
are retained throughout this report.

- Vendor installers, manuals, firmware, and release notes: `original-inputs/`.
- Original input hashes and package manifests: `analysis/extracted/inventory/`.
- Windows Manager 2.0.1.54 and macOS Manager/helper 0.1.0.1 implementation
  references: retained in the local research workspace.
- Firmware 0283 command, flash, signature, and address references: retained in
  the local firmware workspace, with original image hashes recorded above.
- Shared protocol fixtures: `test/fixtures/security-selector-fixtures.json`.
- Native migration bootstrap and its build provenance:
  `native/rdx-service/resources/migration/`.

The local research workspace is optional for ordinary application builds and
tests. Its inventories retain the detailed reference identities and hashes.

## Boundary of what is known

Confirmed exactly: the host file checks, command opcode/modes/offsets/lengths,
all 17 CDBs for 0283, expected host return classes, digital-signature sense,
retry/reconnect behavior, Windows IOCTL path, Mac helper/driver path, installer
contents, drive `0x3B` field decoding/mode dispatch, exact updater-to-flash byte
mapping, sixteen-sector erase range, SPI opcodes, page-boundary programming,
first-four-bytes-last activation strategy, and preservation of flash above
`0x0FFFF`. RSA-1024/RSASSA-PKCS1-v1_5/SHA-256 verification, its embedded public
key, exact signed range, and both outer rolling checks are independently
reproduced by the saved analyzers.

Not yet established: the TUSB9261 mask-ROM recovery implementation, exact
semantic names/types for every reference routine, rollback behavior, the
business meaning of the version-6 opaque manufacturing extension fields, and
the vendor-facing labels for MODE PAGE `0x34` values 1 and 2. The reference
project compiles and links but is relocated, not byte-identical, and not
boot-qualified; it must not be treated as a safe image to flash.

## OpenRDX release validation checkpoints

The following validation and activation details record the earlier OpenRDX implementation checkpoint. Later reconnect changes are recorded in [firmware update development](../development/firmware-updates.md). The live capability check remains authoritative for receiver eligibility.

Vendor `.BIN` images retain their RSA verification. OpenRDX images explicitly use the `OPENRDX1` integrity format; failure of vendor RSA verification never falls back to accepting arbitrary unsigned firmware. The marker and SHA-256 digest provide integrity, not publisher authentication.

The main process opens a bounded regular manifest without following symlinks and checks the selected filename, release version, receiver requirement, template identity, whole-image hash, and boot-region hash. It sends only the two hashes and release version with the immutable image snapshot to the native service. The service independently checks these hashes, the fixed 62,110-byte container, the pinned metadata prefix, all structural and rolling checks, the TI boot records, and the exact marker/digest/zero-padded integrity block. Receiver eligibility is rechecked through the registry-owned live handle before any write.

The release manifest supplies the expected post-update inquiry revision: `1.07` means `0107`. The retained vendor container header says `0283` and must not be used as the installed OpenRDX release. Manifests older than the release-based `1.06` version scheme are rejected because that mapping is not established for them.

After mode-5, the native worker polls for up to 15 seconds for activation. A changed reported revision or clean disappearance/reappearance permits reopening the same exact device identity. For a same-version reinstall, a successful mode-5 `GOOD` reply also permits fresh readback after one second: the OpenRDX receiver sends `GOOD` only after image validation and boot-vector commit, then schedules reset after five 100-ms ticks. The reference PowerShell updater likewise waits one second before checking presence. This path records confirmed commit, not an observed disconnect. Failed probes do not count as disappearance, and every accepted binding undergoes fresh identity, empty-bay, and expected-revision checks. An uncertain finalizer reply still requires activation evidence or the existing single finalizer retry; an unchanged revision after two uncertain replies cannot succeed. A timeout or wrong readback remains a failure; programming may already have completed at that point.

## Evidence and limits

The implementation follows the companion OpenRDX repository's primary sources:

- `scripts/build_rdx_update_container.py`: container size, fixed vendor template, integrity block, and release-manifest hashes.
- `src/rdx_mount/rdx_manager_protocol.c`: sequential mode-4 reception, mode-5 finalization, integrity verification, and delayed reset.
- `src/rdx_mount/rti.c`: periodic reset ticks.
- `src/rdx_mount/scsi.c`: release-derived inquiry revision.
- `scripts/rdx_manager_firmware_update.ps1`: installed receiver whitelist and paired-manifest checks.

The earlier in-place-update investigation inspected a local `OpenRDX-v1-07.bin` build, SHA-256 `e08e58a4b8a2f42b8194c9afc50321f42682f0b46132c00035180c218e14714f`; its boot region is `c18ebc570170e4a1c9b3543d5c93543ca65d85bdd84e30fecd85dec32a6f5bc1`. The source release resides in the companion `OpenRDX/dist` directory; it is not copied into immutable vendor inputs.

The first-installation workflow instead pins the published container SHA-256 `1e26a407d5178f1344682798b7ab935f407fe2ce160fb3d03354cf823a951a9e` and release version `1.07`. It does not admit the earlier local build as a migration image.

Automated tests cover registration, rejected manifests, tampered containers, unchanged vendor RSA rejection, receiver eligibility, exact transfer commands, delayed activation, and incorrect readback. These use simulated transports and do not prove installation on physical hardware. No physical firmware write is part of those tests.
