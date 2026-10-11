<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# MCP verification

This records host-side implementation evidence for the embedded MCP interface. It does not certify physical firmware, format, eject, diagnostic, or security operations.

## Scope

The application exposes 49 named tools, all 20 current high-level operation kinds, all 25 feature-manifest entries, ten fixed JSON resources, and device/operation resource templates. GUI and MCP reuse the validated main-process dispatcher and the same native operation coordinator. Endpoint configuration remains a local desktop control. Eight locale catalogs include the MCP dialog.

## Protocol and boundary evidence

The focused suites use actual SDK HTTP clients and child stdio clients alongside injected deterministic device services. Coverage includes:

- Shared GUI/MCP operation exclusion, stale revisions, rejected lifecycle events, and accepted terminal history.
- Strict tool arguments and response shapes, complete route/operation coverage, capability failures, and sanitized exceptions.
- Missing/incorrect bearer credentials, invalid Host and Origin, malformed JSON, fixed-length and chunked oversized requests.
- Legacy HTTP polling capabilities, modern HTTP subscriptions, and legacy/modern stdio subscriptions with encoded per-operation URIs.
- First-event history eviction, broken stdout after initialization, and framing failure before initialization without orphaning the bridge.
- Persisted opt-in, bind failure/retry, serialized settings changes, private token files, symlink rejection, and token-free clipboard/renderer state.
- Direct firmware path validation, changed-file rejection, one-use claims, redacted report reads, exclusive generated exports, and preserved GUI chooser contracts.
- Modal loading, validation, error containment, copy, closing/focus, language refresh, close/reopen races, and missing bridge behavior.

`test/mcp-server.test.mjs` also proves that the normal exit response arrives before the endpoint closes. Closing a connection does not act as operation cancellation.

Independent review found and resolved incorrect legacy subscription advertisement and stdio teardown gaps. The final review found no outstanding issues in the backend, UI, or production main-process integration.

## Real application evidence

Command: `env -u ELECTRON_RUN_AS_NODE npm run test:mcp:electron` under Node.js 22.16.0.

The harness imports the production Electron main module, runs the real preload and renderer, and isolates only the application's root lookup and persisted preferences. The test enabled MCP through the modal, copied and parsed its actual clipboard configuration, authenticated an SDK client, discovered 49 tools, read application/service/capability/settings state, round-tripped a safe preference, and disabled the listener through the modal. It observed no renderer/preload errors and verified `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`.

The actual runtime reported `service: unavailable` and `hardwareReady: false`. Inventory was unavailable, so this run provides no live RDX device-value or mutation proof. The MCP endpoint and configuration UI remained functional in that state.

Artifacts generated in the ignored test output directory:

- `test-results/mcp/acceptance.json`
- `test-results/mcp/settings-1024x768.png`
- `test-results/mcp/settings-1440x900.png`

Both screenshots were inspected. The dialog fits within each viewport, shows the listening endpoint and copy success, and exposes no token. Firmware/package signing, distribution, and physical device acceptance remain separate work.

## Regression commands

All commands use Node.js 22.16.0.

```sh
npm run test:mcp
npm test
env -u ELECTRON_RUN_AS_NODE npm run smoke
npm run format:check
git diff --check
```

Existing concurrent firmware and renderer work was preserved. The full suite caught terminal punctuation on a newly added firmware reason; only its final punctuation was removed to retain the existing sentence-fragment localization contract. The visual command regenerates the shared screenshot matrix for the new topbar control. No source evidence, credentials, packaging output, or unrelated changes were staged or published.

Final results:

| Check                                 | Result                                                                                        |
| ------------------------------------- | --------------------------------------------------------------------------------------------- |
| `npm run test:mcp`                    | 48 passed, 0 failed                                                                           |
| MCP plus complete localization suites | 55 passed, 0 failed                                                                           |
| `npm run test:mcp:electron`           | Passed; 49 tools, 20 operation kinds, real UI enable/copy/disable, both screenshots inspected |
| `npm run smoke`                       | Passed; renderer mounted, service unavailable, no hardware claim                              |
| `npm run format:check`                | Passed                                                                                        |
| `git diff --check`                    | Passed                                                                                        |
| Full `npm test`                       | 695 tests: 692 passed, 3 failed across two visual-test groups                                 |

The full-suite failures were a focus-dependent `during-transition` subtest and its parent, plus the consecutive-screenshot test's checkout-state comparison. The first observed `windowFocusedAtTraversal: false`; the latter detected `docs/verification/mcp-verification.md` being added between its two runs. Other Electron test processes were also present on the host during verification.

A targeted rerun of those two groups passed both console-injection subtests and their parent. The consecutive-screenshot check still did not produce its completion marker during its approximately 90-second command window (3 passed, 1 failed in that rerun). It remains an unresolved broader visual-test limitation; the full suite is not claimed green. The dedicated MCP screenshots and real-application acceptance passed independently.
