<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Scroll and refresh behavior

The 2026-09-11 report showed the Encryption tab repeatedly returning to the top while the user tried to read lower controls.

## Cause and change

`src/renderer/app-controller.mjs` previously reconciled mounted DOM only for Status and Utilities. Encryption and Tests replaced `#app.innerHTML` on every store update. Auto Scan publishes updates approximately once a second, destroying and recreating the desktop `.area-panel` scroll owner. Restoring keyboard focus with `preventScroll` cannot retain the position of a removed scrolling element.

All four tabs now use incremental shell reconciliation after initial mount. The active panel retains its identity during background refreshes. Changing tabs still replaces the panel because each tab has a distinct panel ID.

Encryption continues to remount its callback-owning inner view with the current security model. This change does not reuse stale security callbacks or retain transient password input across that remount.

## Regression coverage

`test/renderer-scroll-refresh.test.mjs` replays three complete Auto Scan cycles in each tab, checking the original panel identity, scroll position and keyboard focus. Before the change, Encryption and Tests failed the panel-identity assertion; Status and Utilities passed. All four pass with the fix.

`test/encryption-production-integration.test.mjs` also verifies that callbacks still advance and submit a fixture-only workflow after refresh, transient passwords are cleared on remount, and the outer scroll panel remains mounted. No security command is sent to physical hardware by these tests.

## Verification

- Focused renderer, all-tab scroll and Encryption workflow suites: 38 passed. After strengthening the callback refresh assertions, the seven scroll/workflow tests passed again.
- `npm test`: 708 passed, two failures in the real Electron visual-QA tests. One capture timed out; another reported `windowFocusedAtTraversal: false` and an absent focus ring. A separate rerun of those two tests also failed: the consecutive-capture test reported missing window focus, and the raster-noise test timed out before its completion marker. These failures are not represented as passing checks.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke`: passed with a mounted renderer; its unprivileged service was unavailable.
- `npm run format:check` and `git diff --check`: passed.
- The user restarted the application and explicitly confirmed that scrolling in Encryption now stays in place with Auto Scan enabled. The computer-use tool could read the real window, but its scroll/click actions failed; the final live scroll verification is the user's confirmation, not an agent-generated visual claim.
