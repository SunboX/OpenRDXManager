<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Installed binary USB recovery audit — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

Later [live ROM-loader qualification](rom-loader-qualification-2026-10-08.md)
confirmed J7 entry and reported flash presence. The offline findings below
remain applicable; programming and rollback are still unqualified.

The bounded offline investigation found no qualified, non-destructive recovery
path through the closed receiver's USB connection. The exact installed binary
rejects normal firmware download at the same manufacturing latch check as the
failing Serial query. Legacy unlock/erase commands and the inspected vendor
request handler provide no alternative. This closes the proposed offline
investigation; it does not prove that every undocumented hardware route is
impossible.

No device was opened or commanded during this audit. No firmware write, reset,
erase, RAM write or interlock bypass was performed on hardware. The corrected
firmware and private migration bootstrap remain uninstalled and hardware
unvalidated. Normal Windows/macOS updates remain unresolved.

## Exact input and method

The full native Windows snapshot is 262,144 bytes, SHA-256
`027e4a699c5589bda268b92efc3f76143b9790a18e13da43381957aeb5e3ee32`.
Its first 61,710 bytes have SHA-256
`abf7a4156b605fbfd62d123543389ea013e9ceb9828e0a1d48f5bb37da1fa5c6`
and exactly equal the boot region of the historical container at firmware
commit `01cc3814664bb6fdbe72ecfd1e9dd3dd52a48e9c`.

`native-windows-20261008-1/audit-installed-binary.py`, outside Git, validates
these hashes, the historical container hash, the 13-byte ROM header and the
runtime checksum before analysis. It executes the captured Thumb instruction
bytes with Unicorn 2.1.4 and inspects their instruction layout with Capstone 5.0.9.

Names come from the preserved corrected TI 5.2.9 map, with the installed
post-BOT text displacement accounted for. Six-instruction entry anchors were
compared for 14 functions; branch destinations alone were normalized for those
comparisons. The emulator executes installed bytes, not the corrected image.

The fixture explicitly zeros the mapped BSS range `[0x0800E93C,0x0800FBFC)`
and then sets the manufacturing latch at `0x0800F200` to each tested value.
This is synthetic RAM, not a captured boot or evidence that installed firmware
zeros BSS. Other command state starts inactive. The model records instruction
traces, stops before `SpiOps` or `system_reset`, and substitutes a return from
`usb_hal_disconnect`. Instruction and time budgets fail closed. It has no
device API. It does not model USB transport, boot ROM, interrupts, flash timing
or physical reset behavior. Linear instruction listings may include embedded data;
only execution traces identify instructions actually executed in each case.

## Results

All 271 bounded cases passed their assertions:

| Installed code exercised                                 | Synthetic condition                                           | Result                                                      |
| -------------------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------- |
| Serial query `3B025300000100000000`                      | Latch 0                                                       | Status 0; no trapped effect                                 |
| Same Serial query                                        | Latch 1 or `FFFFFFFF`                                         | Status 11, invalid CDB field; no effect                     |
| Mode 4, offset 0, 512-byte first chunk                   | Latch 0                                                       | Reaches SPI write-enable; stopped before SPI execution      |
| Same first chunk                                         | Latch 1 or `FFFFFFFF`                                         | Status 11 before any SPI effect                             |
| Mode 5 activation                                        | Latch 1 or `FFFFFFFF`                                         | Status 11 before any SPI effect                             |
| Mode 5 activation                                        | Latch 0, no completed transfer                                | Status 11; transfer sequencing still enforced               |
| Manufacturing query `3B024D00000100000000`               | Latch 0, 1 or `FFFFFFFF`                                      | Status 0 in all three cases; no effect                      |
| Legacy TI SCSI unlock `E1` and erase `E2`, six-byte CDBs | Synthetic initialized state                                   | Status 10, invalid opcode; no effect                        |
| TI SCSI reset `E6`, six-byte CDB                         | Synthetic initialized state                                   | USB disconnect, then trapped global reset; no SPI operation |
| Vendor host-to-device request numbers `00`–`FF`          | `bmRequestType=40`, `wValue=0037`, `wIndex=0055`, `wLength=0` | All 256 return error 1 without effect                       |

The vendor sweep covers those setup fields, not all USB packet combinations.
Static inspection of the entire installed handler also shows that it only
accepts the device-to-host GET_PID branch with request `70` and length 2.

### Admission and the observed query asymmetry

At `0x080062A6`, the installed Write Buffer handler calls the latch reader at
`0x0800B65C`. The following comparison branches to invalid-field return when
the value is nonzero, before Serial query, Mode 4 download or Mode 5 activation
dispatch. The reader loads the word at `0x0800F200`.

Manufacturing capability uses its own query branch and does not inspect this
latch. This reproduces the observed Manufacturing-GOOD / Serial-`05/24/00`
asymmetry under a synthetic nonzero latch. The actual live latch value remains
unknown. The result supports the existing initializer diagnosis; it does not
establish the cause from the sense response alone.

Changing a Manager readiness check, chunk size or host OS would not remove
this installed receiver check. The clear-latch first-chunk case is a positive
control for reaching SPI admission, not evidence of a successful update.

### Reset, vendor requests and retained HID code

The installed SCSI dispatcher has no E1/E2 handler. E6 calls USB disconnect
and `system_reset`. The installed reset routine at `0x0800CB5C` writes
`0x8000` to `0xFFFFFFE0` and returns. It contains no SPI erase or direct ROM
branch. This is not evidence that resetting the existing valid SPI image
would select ROM, and no reset was sent to test that assumption.

The vendor unlock/erase example in `src/rdx_mount/usb_vendor.c` is disabled
with `#if 0`. The captured handler confirms its absence; its host-to-device
branch simply returns an error.

Retained HID code is present in the binary. Its poison-flash branch at
`0x0800A59C` leads to SPI write-enable at `0x0800A5AC`, followed by chip-erase
opcode `C7` at `0x0800A5B2` and another SPI call at `0x0800A5BA`.
Its download-setup branch sets a RAM/flash flag and page counter; that alone
is not a RAM loader. Register-write functionality is also present, but using
it to change the safety latch would be an interlock bypass.

The earlier live Windows inventory exposed mass storage and its children,
with no matching HID or ROM instance. That absence alone does not prove every
control-transfer handler unreachable. Neither retained HID code nor a
destructive erase sequence establishes a qualified closed-enclosure route.
No HID command was sent, and these branches were inspected statically rather
than counted among the 271 execution cases.

## Stop condition and next useful step

Do not repeat ordinary update attempts or experiment with erase, poison-flash
or RAM writes on this receiver. The next useful recovery qualification is the
board's J7 ROM-loader route when the user chooses to open the enclosure.
That still uses USB for communication, but requires physical access for ROM
entry. J7 has not been fitted or tested in this investigation.

The initial physical stage must establish the exact board procedure, bind one
ROM instance to this receiver and confirm flash presence without programming.
The installed tool's 65,535-byte full-image limit remains relevant: J7 entry
does not establish restoration of the 256 KiB backup. A reviewed programming
and rollback procedure for the small private bootstrap, followed by physical
boot and complete SPI readback, remains necessary before any firmware write.

The existing [native Windows report](native-windows-investigation-2026-10-08.md)
records the tool limitation, bootstrap qualification and unresolved QA results.
Nothing in this audit qualifies the bootstrap for hardware or changes those
results.

## Private reproducibility evidence

Paths below are relative to the transfer folder and remain outside Git:

- `native-windows-20261008-1/audit-installed-binary.py`: analysis source.
- `native-windows-20261008-1/installed-binary-audit/evidence.json`: exact input
  hashes, function anchors, synthetic state, all 271 results and executed traces.
- `native-windows-20261008-1/installed-binary-audit/*.txt`: installed-byte
  instruction listing for the inspected routines.
- `native-windows-20261008-1/installed-binary-audit.log` and
  `installed-binary-audit-exit.txt`: final run output and status.
- `native-windows-20261008-1/EVIDENCE_MANIFEST.json`: SHA-256 inventory including
  this report and audit outputs, with both retained snapshots reverified.

Only analysis scripts and documentation changed in this follow-up. No
application or firmware production source changed, so no new application
runtime or cross-platform update success is claimed.
