<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows BOT cleanup fix — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

**A receiver error-cleanup defect is fixed and TI-built, not deployed. This is not
a fix for the original first-chunk rejection.** No additional firmware
write, activation, reset, recovery operation, or driver change was performed.

## Connected-device readback

The approved read-only comparison completed at `2026-09-15T17:46:30.0465694Z`.
Two separate reads of the 61,710-byte SPI boot region matched each other and the
approved OpenRDX 1.10 container's boot slice exactly: **zero differing bytes**.
All three SHA-256 values are
`abf7a4156b605fbfd62d123543389ea013e9ceb9828e0a1d48f5bb37da1fa5c6`.
The boot marker is not erased.

The probe pinned the selected dock identity before, between, and after reads,
and pinned the 62,110-byte container hash
`4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a`.
Its only permitted device commands were fixed standard/VPD83 INQUIRY and bounded
E7 flash reads. Payloads were compared in memory, not saved as a flash dump.
The result is `read-only-boot-compare-20260915.json` in the Windows staging root
recorded in the [live test report](windows-live-firmware-test-2026-09-15.md).

This establishes the stored boot bytes, not an independent measurement of
executing RAM or of the receiver's command inputs at the earlier rejection.

## Reproduced defect and focused correction

Receiver paths below are relative to the adjacent `../../../OpenRDX` checkout.

`src/rdx_mount/usb_hal_isr.c::usb_hal_handle_xfer_complete` subtracts completed
TRB bytes from `dBytesRemaining`, accumulates `dByteCount`, and clears
`bXferActive` before calling BOT. When the resulting SCSI command fails,
`src/rdx_mount/ums_bot.c::ums_bot_xfer_cleanup` used to subtract the same bytes
again. A completely received rejected request therefore left a negative
remaining count instead of zero. **Correction after TI review:** production
`include/rdx_mount/usb_hal.h:428` uses signed `INT32_T`, not the unsigned type in
the initial host fixture. The original signed code produces `-4096`, with zero
OUT cancellations and zero OUT stalls. The previous wraparound/stall explanation
was incorrect; the double accounting itself is reproduced.

The correction restricts the cleanup's OUT accounting/cancellation block to an
**active** OUT transfer. Already completed transfers retain their counters;
active partial transfers still cancel/stall, active completed transfers still
become inactive, and IN cleanup remains unchanged. No download validation,
authentication, mutation interlock, chunk size, or activation behavior changed.

New receiver regression sources:

- `tests/test_bot_cleanup.py` compiles the actual cleanup function with configured
  MSVC or a host C compiler and runs it without device access.
- `tests/fixtures/bot_cleanup_probe.c` covers seven completed/partial/active/
  repeated/cancellation/IN cleanup scenarios.
- `README.md` labels the separate TI-built development candidate as not hardware verified.

## Receive-path replay and limits

Manager analysis tooling now supports an optional `--bot` replay:
`analysis/scripts/review_receiver_offline.mjs` and
`analysis/scripts/receiver_bot_fixture.c`. It extracts actual CBW validation,
state selection, receive dispatch, OUT completion, CSW publication, cleanup and
USB HAL completion accounting, alongside the existing real receiver checks.
Only extracted `inline` linkage is changed for the host compiler.

Registers/TRBs, endpoint request setup, outer SCSI dispatch and SPI remain
RAM-only models. In particular, request rounding/start fields are modelled,
not actual controller execution; this is neither a TI ABI test nor a USB capture.

The replay accepts all sixteen normal chunks at both 512- and 1,024-byte endpoint
maximum packet sizes, including the 670-byte final chunk. It also injects eight
separate short completions for a declared 4,096-byte chunk. That injection yields
the invalid-field error before SPI and reproduces the cleanup double subtraction. It does
**not** show that such short completions occurred on the connected dock or that
an arbitrary sequence of short transfers is valid bus behavior. Padded CDBs and
an injected manufacturing latch are independently rejected before SPI as well.

The corrected cleanup invariant failed against the original source (red run,
exit 1) and passed after the patch. The corrected signed Manager replay passes
**131 checks** in `C:/Users/afiedler/rdx-bot-signed-review-20260915/`.
The declarations are now extracted and type-checked against the real endpoint
header; a Node regression test rejects signedness drift. The focused production
cleanup test passes all seven scenarios.
The primary rejection precedes cleanup, so the patch is not claimed to fix it.

## Verification and retained evidence

Historical replay evidence (before the signedness correction) is under `C:/Users/afiedler/`:

- `rdx-bot-review-20260915-run2/`: original-source behavior, 130 checks.
- `rdx-bot-review-20260915-red/`: expected cleanup invariant fails before the fix.
- `rdx-bot-review-20260915-green/`: corrected source, 130 checks, compiler exit 0.

Each successful replay has `manifest.json` with input/generated hashes,
`build.txt`, `cases.txt`, and its RAM-only executable. MSVC 14.40.33807 compiled
with C11, `/W3 /WX`; the focused seven-scenario test uses `/W4 /WX`.
The one initial probe-test cleanup error was a Windows lock on its just-executed
temporary executable; a bounded permission-error cleanup retry resolves it
without weakening compilation or test assertions.

Historical Windows verification before the compiler handoff:

- `python -m unittest discover -s tests -v` in the receiver checkout: **300
  tests, 259 passed, 41 skipped**, exit 0, 70.728 seconds. Skips include existing
  probes requiring a `cc` executable; the new focused probe actually ran under
  MSVC. The final log is `rdx-bot-review-20260915-green/python-suite-final.txt`.
  The process inherited only a scoped Git safe-directory setting for this UNC
  repository, plus `core.safecrlf=false`; no persistent Git setting changed.
- Original receiver-only replay after the fixture extension: all 27 checks pass
  in `rdx-receiver-review-20260915-final/`.
- Manager `npm run format:check`, separate analysis-script formatting/syntax
  checks, and focused Git whitespace checks pass.
- Receiver `dist/OpenRDX-v1-10.bin` retains the exact pinned hash above and no
  `dist/` change appears in the focused status check.

Manager application/runtime source was not changed in this pass, so its Node
runtime tests and Electron smoke were not rerun. Prior live smoke and firmware
test outcomes remain as recorded in the linked live-test report.

The Windows TI tool resolver reports both required tools absent:
`C:/ti/ti-cgt-arm_5.2.5/bin/armcl.exe` and
`C:/ti/ti-cgt-arm_5.2.5/bin/armhex.exe`.
No substitute compiler was used to produce firmware. The returned Mac/Wine TI
5.2.9 build created a separate verified candidate with container SHA-256
`879d97119d1510a1e2ab6392dd5ee135f883cf5fea1332dd8a867efb48618f06`.
All 69 returned files were independently checksum-verified on Windows, including
the source patch and full TI instruction listing. The original shared `dist/` remains
unchanged. Nothing was flashed from the modified source.

The remaining hardware diagnostic gap is the actual CBW/CDB, data-out completion
length and receiver state behind the captured `05/24/00` response. The recorded
Windows SPTI submission is valid, but it does not measure that device-side
boundary. A speculative retry or protocol workaround is not hardware proof.
