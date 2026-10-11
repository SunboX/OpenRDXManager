<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Status availability

The text “Not supported by this device firmware” was not a firmware capability result. It was the translation of `field-decoder-unavailable`, used both for an unimplemented field and for a field missing from decoded status evidence.

## Confirmed implementation findings

- `native/rdx-service/src/platform/status.rs`: drive policy is explicitly unavailable with `field-decoder-unavailable`; no policy query or firmware capability check runs for this field.
- `native/rdx-service/src/platform/media_status.rs`, `media_status_evidence`: cartridge status, load count, bytes written and bytes read are extracted from LOG SENSE page `0x21`, parameters `0`, `1`, `5` and `6`.
- `native/rdx-service/src/platform/registry/presentation.rs`, `probe_reason`: a successful transport response with a missing decoded value becomes `field-decoder-unavailable`. A missing response becomes `status-probe-unavailable`. Neither outcome proves an unsupported feature.
- `src/renderer/views/status-view.mjs`: the cartridge status card previously always received healthy styling, including when its value was unknown or an error.

The UI now says “Not available in OpenRDXManager” for missing decoded fields, “Could not read device status” for unavailable queries, and “Not reported” for absent values. These distinctions are translated into all eight supported languages. Only reported `Good` cartridge status receives healthy styling.

## Vendor evidence

the macOS Manager 0.1.0.1 implementation reference contains `SCLsnCartInfoPg::GetCartStatusSafe`, `GetCartLoadCountSafe`, `GetCartDataWrittenSafe` and `GetCartDataReadSafe`. The original application supports reading these values. This does not prove that a particular cartridge supplied them successfully.

`analysis/extracted/help/windows-2.0.1.54/doc/Mgmt_Popup_Status-DDA.htm` describes drive policy as the host performance policy (“Better Performance”). It is not a generic cartridge-firmware capability.

## Initial physical evidence and uncertainty

The supplied screenshot and the running Electron window show dock serial `7360242889` on firmware `2.83`, with cartridge `15293EK18B`. Cartridge identity and temperature are readable; the four cartridge LOG-page values above are unavailable. The page-available support label means a response reached the service, not that the complete page decoded successfully.

At that stage, the raw page response had not been captured. The existing helper was in the user’s privileged session; the agent’s independent noninteractive sudo check required a password. That initial evidence did not justify a parser fallback, invented counter value, firmware change, or physical capability conclusion. Only presentation had been corrected; the later vendor comparison below established the decoder defect.

## Verification

- Focused renderer/firmware-display tests: 18 passed; the new assertions first failed against the old wording and unconditional healthy styling.
- `npm test`: 703 passed, one failure in the consecutive visual-QA screenshot checksum comparison. The manifest and Git-status comparisons agreed; the screenshot-set hashes differed.
- `npm run smoke`: passed with a mounted renderer and an unavailable unprivileged service. This proves application startup, not hardware access.
- `npm run format:check` and `git diff --check`: passed.
- After reloading the existing idle window, its accessibility tree shows the corrected labels on the same live dock and cartridge. The computer-use screenshot tool returned a blank image despite that populated tree, so it is not retained as visual proof.

## Vendor comparison and decoder fix

The user's Windows RDX Manager capture at 07:26 on 2026-09-11 shows the same dock on firmware `0283` and cartridge reporting Good, load count 21, approximately 2.17 GB read and 95.00 MB written. The following macOS OpenRDXManager capture still lacks those four fields. Temperature (30 °C) and cartridge identity agree. This is user-supplied physical evidence, not a simulated response.

### Root cause in the original firmware

The opcode `0x4D` entry in `analysis/private-firmware/tables/scsi_command_descriptor_table_0x0800DF80.hex` points to Thumb handler `0x08000615` (`FUN_08000614`). Its reference description is in `analysis/private-firmware/firmware-update-evidence.txt`, starting at line 1385.

For page `0x21`, that handler:

1. Allocates a zero-filled `0x74`-byte response (`FUN_0800bdb8` clears the allocation).
2. Advertises a `0x70`-byte body in the page header.
3. Writes fourteen parameters: parameter 0 has a two-byte value; parameters 1 through 13 have four-byte values.
4. Ends the records at `0x72`, leaving two zero bytes inside the declared response.

The record body is therefore `6 + 13 × 8 = 110` bytes, while the advertised body is 112 bytes. Our generic parser attempted to parse the last two zeros as another four-byte parameter header and rejected the entire page with `PayloadTooShort { minimum: 4, actual: 2 }`. The original Manager's safe fixed-field getters read the complete earlier records and do not require a parameter header at that tail.

The parser now accepts exactly that reserved tail: cartridge page `0x21`, total length `0x74`, complete records ending at `0x72`, and two zero bytes. Existing total-length checks and parameter bounds still apply. Other trailing lengths, nonzero bytes, drive-page tails and truncated responses remain invalid. No firmware revision string, device serial, synthetic telemetry or guessed offset fallback controls this compatibility rule.

### Other differences in the screenshots

The Protection card previously prioritized an unavailable encryption result over a reported write-protect state. It now displays known write protection when encryption telemetry is absent, while preserving priority for an explicitly reported encryption state.

Drive policy is different: Windows RDX Manager reads Windows removal policy, including `Classpnp\UserRemovalPolicy`, and displays Better Performance or Quick Removal. See the Windows Manager 2.0.1.54 implementation reference around lines 16910 and 78094. An unavailable drive-policy field is now labeled “Windows-only setting” on macOS and Linux. No Windows policy value is fabricated on those platforms.

### Regression evidence

`native/rdx-service/tests/cartridge_log_padding.rs` reconstructs the original firmware's framing with illustrative counter values; it is not presented as a raw capture. Before the fix it reproduced the two-byte-header failure. `platform_registry/media_refresh.rs` independently reproduced the unavailable public status snapshot. Both now preserve the reported status, load count, read/write counters and write protection. Negative tests retain strict rejection of truncated and malformed responses. `test/status-vendor-parity.test.mjs` covers the user-visible values, protection fallback, encryption priority and host-specific policy wording.

### Verification of the decoder fix

- `npm run native:test -- --test cartridge_log_padding --test platform_registry`: 39 passed.
- `npm run native:test -- -- --skip scan_without_a_platform_adapter_is_a_safe_empty_success`: 429 passed, with the named existing CLI test excluded.
- `npm run native:check` and `npm run native:check:no-default`: passed, including Clippy with warnings denied.
- `node --test test/status-vendor-parity.test.mjs test/renderer-status-dom.test.mjs`: 13 passed.
- `npm test`: 706 passed, one failure in `verification timeout terminates the complete command tree` (the descendant process was still observable at the immediate assertion). The unchanged `test/platform-verification.test.mjs` suite then passed all nine tests in a standalone rerun. The complete run is not represented as all green.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke`: passed; the renderer mounted. Its unprivileged service was unavailable, so this check alone is not hardware proof.
- `npm run format:check` and `git diff --check`: passed.

### Live hardware verification after restart

The user restarted the development application at 07:46 on 2026-09-11, loading the rebuilt native helper. The live Electron window was inspected through its accessibility tree and a nonblank screenshot. It identifies dock `7360242889`, firmware `2.83`, and IMATION cartridge `15293EK18B`, and now shows:

| Field                | Live result                     |
| -------------------- | ------------------------------- |
| Cartridge status     | Good                            |
| Cartridge load count | 21                              |
| Bytes read           | 2.19 GB                         |
| Bytes written        | 95.0 MB                         |
| Temperature          | 30 °C                           |
| Protection           | Read / write — Write protection |
| Drive policy         | Windows-only setting            |

These are observed hardware-backed UI values, not fixture output. No firmware update or cartridge write was performed for this verification. A raw protocol response was not captured; the response framing is supported by the firmware response builder, regression tests and successful live readback after the parser change.
