<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows fix verification — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

This VM checkpoint predates the matched macOS investigation, complete current
SPI backup and offline repair candidate. See
[the native Windows handoff](native-windows-firmware-handoff-2026-10-08.md)
for the later state and fresh commit verification, including remaining Mac QA failures.

This report supersedes the older broad-test failures in the September Windows
reports. It is software verification on Windows 11 ARM64 in Parallels with the
x64 development runtime, not an all-features hardware or release qualification.
Existing unrelated repository changes and original vendor inputs were preserved.

## Corrections

- Windows MSVC integration-test executables now embed an `asInvoker` UAC
  manifest. The manifestless `compatibility_setup` test previously triggered
  Windows installer detection and failed with error 740. Cargo's test-only link
  directives leave production executable privileges unchanged. See
  [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
  and [Microsoft's manifest option](https://learn.microsoft.com/en-us/cpp/build/reference/manifestuac-embeds-uac-information-in-manifest?view=msvc-170).
- The signed-firmware worker fixture now has one bounded 40-second deadline
  instead of assuming every event arrives within two seconds under load. Exact
  event count, terminal success, command counts and consumed-token checks remain.
  No production firmware timeout or retry policy changed.
- Windows visual QA uses integer 1x sizing and software rasterization in the
  isolated harness. This resolves the observed 769-DIP minimum-height rounding
  and cross-process virtual-GPU raster differences. Production DPI, minimum
  size and window security settings are unchanged; strict bounds, painted
  anchors, console-error rejection and raster-noise limits remain enforced.
- Electron QA and raster comparison select disposable profiles synchronously
  before readiness. They no longer share the real application's profile/cache.
  Parent tests clean their own profiles after child exit. The negative stale
  raster fixture is resized to the actual capture dimensions so its rejection
  tests missing anchors rather than a DPI mismatch. See
  [Electron application paths](https://www.electronjs.org/docs/latest/api/app).
- Stable visual manifests sort resource URLs without dropping duplicates or
  forbidden URLs. Raw inspection validation still rejects remote resources.
  Diagnostics identify changing manifest fields and meaningful raster changes.
  The observed 2px/3px keyboard-outline variation is retained in per-run capture
  metrics, not stable post-blur screenshot manifests. Raw inspection now also
  rejects missing, malformed and sub-2px measured rings; required focus/traversal
  checks remain. A focused regression verifies both retention and rejection.
- Main-process startup diagnostics now include a bounded failure category.
  Arbitrary native messages and filesystem paths are not emitted by this helper.
- QA windows explicitly disable background frame throttling while retaining
  production security and minimum-size preferences. Frame-based waits must not
  depend on which application has desktop focus. This is a harness-only setting;
  see [Electron's window preferences](https://www.electronjs.org/docs/latest/api/browser-window).
- Output-stream errors terminate the disposable QA process with exit 1 rather
  than opening Electron's blocking exception dialog. Computer Use read the
  abandoned process's actual dialog: `EPIPE: broken pipe, write` at the noise-
  preservation log after its parent timed out. Both stdout and stderr failure
  paths have deterministic tests. Only exact task-owned abandoned process trees
  were stopped after their command lines were verified; no user app was targeted.

## Verification

Commands ran in the source-matched, existing Windows build mirror
`C:/Users/afiedler/rdx-spti-20260915`. No generated output was hand-edited.

| Check                                                                                   | Result                                                                                                                       |
| --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Final-source `npm test`                                                                 | 903 passed, 0 failed, 8 skipped; 911 total; exit 0                                                                           |
| `npm run native:quality`                                                                | Exit 0; formatting, both check/Clippy configurations and rustdoc passed                                                      |
| Native all-feature suites                                                               | 532 passed, 0 failed                                                                                                         |
| Native no-default-feature suites                                                        | 391 passed, 0 failed                                                                                                         |
| Real Electron visual regression                                                         | Two consecutive 62-scene captures stable; canonical evidence unchanged; console and stale/wrong-raster negative cases passed |
| Administrator-approved real `npm run smoke -- --user-data-dir=<existing-local-profile>` | Exit 0; renderer mounted, service ready, native mode, `hardware=true`, `reason=none`                                         |
| Final-source non-elevated `npm run smoke -- --user-data-dir=<existing-local-profile>`   | Exit 0; renderer mounted, native service ready; `hardware=false`, `raw-transport-unavailable`                                |
| Repository `npm run format:check`                                                       | Exit 0; existing mirror dependency executables supplied on PATH                                                              |
| Focused Git whitespace check                                                            | Exit 0; unrelated parent-repository changes left untouched                                                                   |

Raw logs and diagnostic artifacts are retained in
`C:/Users/afiedler/rdx-all-issues-20261008/`, including `native-quality-final.txt`,
`node-final7.txt`, `compatibility-test.manifest`, and
`elevated-profile-smoke.txt`. Final-source verification is recorded separately
below. The smoke check exited normally; it did not perform a firmware update.

The final corruption-fixture correction was independently exercised through the
public visual-QA command with lifecycle scripts disabled because the runtime had
already been built. It returned the required failure for missing brand anchors,
not a dimension mismatch (`corrupt-fixture.txt`). An intermediate verification
found and corrected a fixture filename mapping mistake (`node-final3.txt`);
that intermediate failed run is not counted as passing verification. A later
run exited before writing its capture manifest (`node-final4.txt`), and another
hit a visual-child timeout and locked cleanup (`node-final5.txt`). These remain
recorded as failed runs, not as hardware failures or passing qualification.
Final-source results after the background/output corrections are recorded below.

## Definitive final-source run

`node-final7.txt` records all 911 tests: 903 passed, none failed, eight skipped,
exit 0. This includes the corrected dimension-valid negative fixture, two
consecutive complete 62-scene Electron captures, unchanged canonical evidence,
wrong-raster replacement and exact injected console-error rejection. The final
source also passes repository `npm run format:check` and the focused Git
whitespace check. All 15 changed executable/test files match the build mirror
by SHA-256 and remain below 1,000 lines.

The passing full run used npm's normal Windows CMD shell in the local build
mirror, with the task's custom `npm_config_script_shell` override removed.
Previous PowerShell-override runs reproduced nested visual-child timeouts
(`node-final5.txt` and `node-final6.txt`); the normal-shell focused run completed
without that timeout and exposed the outline-width difference
(`visual-cmd-shell.txt`). That failing intermediate focused run is retained.
No timeout limit was increased and no failed result was counted as passing.

The serialized final-source non-elevated smoke also passed (`smoke-final.txt`).
Its service was ready but raw hardware transport was unavailable; it is not
hardware-access proof. The separate administrator-approved smoke above reported
hardware access ready (`elevated-profile-smoke.txt`). Neither smoke flashed the
dock, and neither substitutes for the retained-handle firmware readiness probe.

The Codex-hosted default Roaming profile resolves through MSIX app-data
redirection into a package-local cache. The native protected-path policy rejects
that unexpected canonical destination (`windows-log-path-unverified`). A
read-only Win32 final-path probe confirmed the mismatch. The successful smoke
used the already established physical Windows development profile and preserved
its settings. No junction/path-verification safeguard was weakened. An earlier
overlapping addon rebuild failed; final verification commands were serialized.

## Still not repaired on the physical dock

The connected dock remains on revision `0110`. The fresh October 8 retained-
handle probe returned GOOD for the fixed manufacturing capability query, but
CHECK CONDITION `05/24/00` for the fixed serial capability query through both
direct and buffered SPTI. The guarded updater stopped before submission:
**no firmware bytes, reset, or firmware-update operation were sent**.

The corrected TI-compiled receiver candidate remains uninstalled. A fresh
4096-byte manufacturing-sector backup was saved and verified, but that is not a
full current SPI/operational-state backup. Ordinary retries cannot install the
repair through a receiver that rejects its readiness query. Do not clear the
safety interlock or substitute an unqualified full-chip erase.

Installation needs a validated record-preserving recovery route. The documented
board J7 ROM route requires physical access, and this Windows host lacks the
qualified preservation/program/readback workflow. The existing macOS recovery
controller cannot be relabeled as a Windows installer. Loaded-cartridge behavior
also remains unverified while the bay is empty.

See [receiver repair and live-device evidence](windows-receiver-boot-init-fix-2026-09-16.md)
for candidate identity, exact probe/backup hashes and the recovery boundary.
