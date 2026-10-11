<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# High-flash manufacturing and configuration

## Scope and result

This document describes every byte above `0x0FFFF` in the captured 256-KiB
M25PE20 flash and traces the firmware code that reads, validates, changes and
writes it. The analysis is offline; none of the saved scripts opens or changes
an RDX device.

There are only two populated records in the captured area:

| Flash range        |    Size | Captured state            | Actual role                                                  |
| ------------------ | ------: | ------------------------- | ------------------------------------------------------------ |
| `0x10000..0x3DFFF` | 188,416 | all `FF`                  | unused/erased in this unit                                   |
| `0x3E000..0x3E0FF` |     256 | populated, checksum valid | unit manufacturing and USB identity record                   |
| `0x3E100..0x3EFFF` |   3,840 | all `FF`                  | unused remainder of its 4-KiB erase sector                   |
| `0x3F000..0x3F03F` |      64 | populated, checksum valid | persistent operational state record                          |
| `0x3F040..0x3FFFF` |   4,032 | all `FF`                  | includes an erased bootstrap byte and erased fallback record |

The standard RDX Manager firmware update never erases this region. It erases
only `0x00000..0x0FFFF`, so all of the records below survive a normal update.

## Record checksum: exact algorithm

Both the 256-byte and 64-byte records use the same custom four-byte checksum.
It is not CRC32.

```text
lanes = [0x78, 0x56, 0x34, 0x12]

for record offset n from 4 through the last byte:
    lane = (n - 4) modulo 4
    lanes[lane] = (lanes[lane] + record[n]) modulo 256

record[0:4] must equal lanes
```

This is four independent byte sums over interleaved lanes. There is no carry
between lanes. The implementation is at runtime `0x0800ADF4` and
`0x0800B092`.

Captured verification:

| Record               | Stored bytes  | Recalculated bytes | Result |
| -------------------- | ------------- | ------------------ | ------ |
| `0x3E000`, 256 bytes | `3E DB 6E C6` | `3E DB 6E C6`      | valid  |
| `0x3F000`, 64 bytes  | `85 56 34 12` | `85 56 34 12`      | valid  |

The reusable decoder reproducing this result is
`analysis/scripts/decode_high_flash_records.py`. Its machine-readable output is
`analysis/private-firmware/high-flash/high-flash-analysis.json`.

## `0x3E000`: 256-byte unit/manufacturing record

The firmware reads all 256 bytes during startup, recalculates the checksum and
uses compiled defaults if the read fails or the checksum differs. This record
is also exposed to Tandberg factory tooling through SCSI READ BUFFER and WRITE
BUFFER operations.

### Exact field map

| Offset | Size | Type   | Captured value                         | Meaning and confidence                                                                |
| -----: | ---: | ------ | -------------------------------------- | ------------------------------------------------------------------------------------- |
| `0x00` |    4 | bytes  | `3E DB 6E C6`                          | four-lane checksum; proven                                                            |
| `0x04` |    4 | LE32   | `6`                                    | record format version; proven by version-gated import logic                           |
| `0x08` |   10 | ASCII  | `7820999743`                           | unit serial; proven, also used by updater's serial/XOR authorization                  |
| `0x12` |    8 | ASCII  | `TANDBERG`                             | SCSI INQUIRY Vendor ID; proven by original Manager class names                        |
| `0x1A` |   16 | ASCII  | `RDX` plus spaces                      | SCSI INQUIRY Product ID; proven by original Manager class names                       |
| `0x2A` |    2 | bytes  | `00 00`                                | alignment/reserved                                                                    |
| `0x2C` |    4 | LE32   | `1`                                    | Board Revision; exported at payload `0x20`                                            |
| `0x30` |    4 | LE32   | `0`                                    | Board EC Level (engineering-change level); exported at payload `0x24`                 |
| `0x34` |   64 | ASCII  | `306200140256B3A9L5000157` plus spaces | MFG Data                                                                              |
| `0x74` |    2 | bytes  | `00 00`                                | alignment/reserved                                                                    |
| `0x76` |    2 | LE16   | `0x1A5A`                               | runtime USB VID; proven                                                               |
| `0x78` |    2 | LE16   | `0x0006`                               | runtime USB PID; proven                                                               |
| `0x7A` |    8 | ASCII  | `TANDBERG`                             | source for runtime USB manufacturer string; proven                                    |
| `0x82` |   16 | ASCII  | `RDX` plus spaces                      | source for runtime USB product string; proven                                         |
| `0x92` |    2 | bytes  | `00 00`                                | alignment/reserved                                                                    |
| `0x94` |    4 | LE32   | `56` (`0x00000038`)                    | Product Enumeration (`RDX_ProductType_en`), format-version 4+                         |
| `0x98` |    4 | LE32   | `0`                                    | Software Configuration Bitfield, format-version 4+                                    |
| `0x9C` |    8 | ASCII  | `20122021`                             | Date Of Build, format-version 5+; captured representation is `DDMMYYYY` = 20 Dec 2021 |
| `0xA4` |    2 | LE16   | `0x0038`                               | format-version-6+ hardware/behavior selector; `0x38` selects a distinct init path     |
| `0xA6` |   16 | opaque | all zero                               | format-version-6+ factory field, payload `0x7A`; exact meaning unknown                |
| `0xB6` |   16 | opaque | all zero                               | format-version-6+ factory field, payload `0x8A`; exact meaning unknown                |
| `0xC6` |   16 | opaque | all zero                               | format-version-6+ factory field, payload `0x9A`; exact meaning unknown                |
| `0xD6` |   42 | bytes  | all zero                               | reserved/unused by this firmware image                                                |

The formerly visible string `201220218` is not one nine-byte field. It is the
eight-byte field `20122021` immediately followed by the low byte `0x38` of the
separate 16-bit selector at `0xA4`.

The captured Product Enumeration at `0x94` independently also has numeric
value `0x38`. These are separate fields with separate version gates even though
this unit stores the same number in both.

### What the format version controls

The WRITE BUFFER importer treats the LE32 at `0x04` as a structure version:

| Version threshold | Fields accepted in addition to the base fields                  |
| ----------------: | --------------------------------------------------------------- |
|            always | serial, fields at `0x2C/0x30`, 64-byte factory text             |
|             `> 3` | LE32 values at `0x94` and `0x98`; stored format version updated |
|             `> 4` | eight-byte field at `0x9C`                                      |
|             `> 5` | selector at `0xA4` and three 16-byte fields at `0xA6/0xB6/0xC6` |

The captured record is version 6 and therefore uses the full known layout.

### Compiled defaults when the record is invalid

Firmware `0x080024FC` clears the complete record and installs these defaults:

```text
format version          6
serial                  7360242889
INQUIRY Vendor ID      TANDBERG
INQUIRY Product ID     RDX
USB VID                 0x1A5A
USB PID                 0x0006
USB manufacturer       TANDBERG
USB product            RDX
Board Revision          0
Board EC Level          1
Date Of Build           10102010
selector                0x0038
three 16-byte fields    all zero
```

The compiled USB descriptor contains PID `0x0005`, but the valid unit record
overrides it with PID `0x0006` while constructing the runtime device descriptor.
The stored record, not the immutable descriptor template, is authoritative for
the enumerated identity.

## Factory SCSI interface for the unit record

The same SCSI handlers used for firmware transfer contain a distinct
factory/configuration interface. These commands are not part of a normal RDX
Manager firmware update.

The 10-byte CDB layout is:

```text
byte 0      opcode: 0x3C READ BUFFER or 0x3B WRITE BUFFER
byte 1      mode in low five bits
byte 2      buffer ID
bytes 3..5  big-endian 24-bit buffer offset
bytes 6..8  big-endian 24-bit transfer/allocation length
byte 9      control
```

### Read operations

| Command                                      | Returned structure                        |
| -------------------------------------------- | ----------------------------------------- |
| READ BUFFER mode `2`, ID `2`, length `0xAC`  | factory-info view of the unit record      |
| READ BUFFER mode `2`, ID `10`, length `0x20` | USB identity view                         |
| READ BUFFER mode `3`, ID `2`, length `4`     | buffer descriptor reporting the ID-2 size |

The 172-byte ID-2 response is not a byte-for-byte copy. It is built as follows:

| Response offset | Size |                    Source in `0x3E000` |
| --------------: | ---: | -------------------------------------: |
|          `0x10` |   10 |                          `0x08` serial |
|          `0x1C` |    4 |                  `0x04` format version |
|          `0x20` |    4 |                  `0x2C` Board Revision |
|          `0x24` |    4 |                  `0x30` Board EC Level |
|          `0x28` |   64 |                        `0x34` MFG Data |
|          `0x68` |    4 |             `0x94` Product Enumeration |
|          `0x6C` |    4 | `0x98` Software Configuration Bitfield |
|          `0x70` |    8 |                   `0x9C` Date Of Build |
|          `0x78` |    2 |                                 `0xA4` |
|          `0x7A` |   16 |                                 `0xA6` |
|          `0x8A` |   16 |                                 `0xB6` |
|          `0x9A` |   16 |                                 `0xC6` |

The 32-byte ID-10 response is:

| Response offset | Size | Source                                                    |
| --------------: | ---: | --------------------------------------------------------- |
|    `0x00..0x03` |    4 | zero in generated response; checksum is required on write |
|          `0x04` |    2 | USB VID at record `0x76`                                  |
|          `0x06` |    2 | USB PID at record `0x78`                                  |
|          `0x08` |    8 | USB manufacturer at record `0x7A`                         |
|          `0x10` |   16 | USB product at record `0x82`                              |

### Write operations

WRITE BUFFER mode `2` accepts these buffer IDs:

|  Buffer ID | Expected payload role              | Validation/effect                                                               |
| ---------: | ---------------------------------- | ------------------------------------------------------------------------------- |
|        `2` | `0xAC`-byte factory-info structure | imports the version-gated fields listed above                                   |
| `3` or `4` | secondary identity structure       | copies 8 bytes at payload `0x10` and 16 bytes at payload `0x1C`                 |
|       `10` | `0x20`-byte USB identity structure | verifies the same four-lane checksum, then imports VID/PID/manufacturer/product |

After a successful import, runtime `0x0800C7B0` recalculates the complete
256-byte checksum, erases the 4-KiB sector starting at `0x3E000`, and programs
the first 256 bytes. Internal success is zero. An invalid ID-10 checksum or
unsupported buffer ID returns one to the importer; the WRITE BUFFER handler
turns that into internal status `0x20`, which reaches the host as SCSI failure
rather than a data payload.

## `0x3F000`: 64-byte persistent operational state

This record is loaded after the unit record. Its exact captured content is:

```text
0003F000  85 56 34 12 0D 00 00 00 00 00 00 00 00 00 00 00
0003F010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003F020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0003F030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

### Exact field map

| Offset | Size | Captured value | Meaning                                                                 |
| -----: | ---: | -------------: | ----------------------------------------------------------------------- |
| `0x00` |    4 |  `85 56 34 12` | valid four-lane checksum                                                |
| `0x04` |    4 |           `13` | Drive Load Count; persistent count of successful media/load activations |
| `0x08` |    5 |       all zero | reserved/unreferenced                                                   |
| `0x0D` |    1 |            `0` | saved low two bits for vendor MODE PAGE `0x34`, byte 4                  |
| `0x0E` |   50 |       all zero | reserved/unreferenced                                                   |

The `Load Count` name is printed by the Manager's Drive Info LOG SENSE parser.
The controller increments this field only through runtime `0x0800CD3C`; its
sole caller is in the successful media activation/load transition at
`0x08009640`, reached from START STOP UNIT handling and the internal RDX state
machine. The captured device has recorded 13 loads.

The byte at `0x0D` is proven exactly. MODE SELECT(6/10) page `0x34` accepts a
value in the low two bits of page byte 4. When the CDB Save Pages bit is set,
the value is written here and the record is persisted. MODE SENSE page `0x34`
returns this value; stored zero is normalized to current value `1`. Values 1
and 2 select different RDX state-machine behavior. The vendor's human-readable
names for those two modes are not present in the supplied firmware or Manager.

## `0x3FC00`: 64-byte fallback copy

At startup the firmware follows this order:

1. Read 64 bytes from primary `0x3F000`.
2. Accept it only if its checksum is valid.
3. If it is unreadable or invalid, read 64 bytes from fallback `0x3FC00`.
4. Accept the fallback only if its checksum is valid.
5. If neither is valid, clear the 64-byte RAM record.
6. Apply the optional bootstrap byte at `0x3F190`.
7. Recalculate the checksum and write a new primary record at `0x3F000`.

The captured `0x3FC00..0x3FC3F` is all `FF`, so this unit has no usable fallback
copy.

## `0x3F190`: one-byte mode bootstrap

This byte is consulted only while recovering from an invalid/unreadable
primary state record. Its rule is exact:

```text
if bit 7 is clear:
    value = byte & 3
    if value is 1 or 2:
        state_record[0x0D] = value
```

The captured byte is erased `FF`, so it is ignored. Its function is therefore
a factory bootstrap for the saved vendor MODE PAGE `0x34` value, not a third
general configuration block.

## Erase-sector interaction

The distinction between logical records and physical erase sectors matters:

| Logical write        | SPI sequence                                                   | Physical bytes erased first |
| -------------------- | -------------------------------------------------------------- | --------------------------- |
| rewrite unit record  | `06`, then `20` at `0x3E000`, then `02` page program 256 bytes | `0x3E000..0x3EFFF`          |
| rewrite state record | `06`, then `20` at `0x3F000`, then `02` page program 64 bytes  | `0x3F000..0x3FFFF`          |

Opcode `0x20` is the 4-KiB erase operation used by this firmware. Consequently,
every normal state-record rewrite also erases the bootstrap byte at `0x3F190`
and fallback record at `0x3FC00`. Those two locations are factory/recovery
inputs, not independently maintained live copies.

## Authoritative code locations

| Runtime address            | Reference role                                                                |
| -------------------------- | ----------------------------------------------------------------------------- |
| `0x080024FC`               | load and validate both records; install unit defaults; use fallback/bootstrap |
| `0x08003198`               | import factory WRITE BUFFER payloads into unit record                         |
| `0x08004884`               | SCSI WRITE BUFFER handler                                                     |
| `0x08005C1C`               | SCSI READ BUFFER handler                                                      |
| `0x08005ED4`               | build ID-2 `0xAC`-byte factory response                                       |
| `0x080060F0`               | build runtime USB descriptors from stored identity                            |
| `0x08009C44`               | build ID-10 `0x20`-byte USB identity response                                 |
| `0x08009C84`               | read and validate bootstrap byte `0x3F190`                                    |
| `0x0800ADF4`, `0x0800B092` | exact checksum algorithm                                                      |
| `0x0800C118`, `0x0800C7B0` | checksum, erase and program unit record                                       |
| `0x0800C300`, `0x0800C338` | checksum, erase and program primary state                                     |
| `0x0800CD3C`               | increment persistent transition count                                         |
| `0x0800CD5C`               | read unit record `0x3E000`                                                    |
| `0x0800CEFC`               | persist MODE PAGE `0x34` selection                                            |
| `0x0800CF84`               | read primary state `0x3F000`                                                  |
| `0x0800CF92`               | read fallback state `0x3FC00`                                                 |

The focused extracted algorithm outline and its address manifest are under
`analysis/private-firmware/high-flash/focused-code/`. The complete firmware
source remains under the local firmware source workspace.

## Reproduction

From the Updater folder:

```sh
analysis/scripts/extract_private_firmware.sh
```

Or run only the decoder:

```sh
analysis/scripts/decode_high_flash_records.py \
  analysis/private-firmware/reference-project/Firmware/M25PE20_RDX_original_flash_256KiB.bin \
  --output analysis/private-firmware/high-flash/high-flash-analysis.json
```

Both operations are offline file analysis only.

## Remaining semantic limits

The controller and symbol-bearing Manager binary together prove the
boundaries, types, version gates, default values, checksums, SCSI mappings and
names through Date Of Build. The supplied artifacts do not expose semantic
names for the version-6 selector/three 16-byte fields or the vendor-facing
names for MODE PAGE `0x34` values 1 and 2. Those items remain deliberately
offset-labelled instead of being assigned invented names.

## Original Tandberg type/name evidence

The symbol-bearing macOS Manager identifies the structures as
`SYS_ProductInfo_setOnce_version6`, `SYS_ProductInfo_setMultiple`, and
`SYS_USBWriteOnceParam`. Its `SCRbWriteOnceParams`/`SCWbWriteOnceParams`
methods name Board Revision, Board EC Level, MFG Data, Product Enumeration,
Software Configuration Bitfield, and Date Of Build. `SetOnceDataToString`
reads Product Enumeration at response `0x58`, Software Configuration Bitfield
at `0x5C`, and Date Of Build at `0x60`, matching the controller's source
record offsets `0x94`, `0x98`, and `0x9C` exactly.
