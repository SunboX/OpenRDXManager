<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# macOS worker helper location compatibility amendment

This bounded correction preserves both installation modes required by the authenticated GUI worker plan. Root and independent design review precede implementation. It authorizes no privileged execution, installation, device action or publication.

## Confirmed regression

The signed launchd plist starts `Contents/Library/LaunchServices/openrdx-hardware` inside the installed app. The native client already distinguishes that signed service from the separately installed local service. The new runtime generation, current-executable check and GUI launcher instead require the local standalone helper in both modes. Consequently a valid signed-only installation is refused before native accept, and its worker cannot start. This is a source-confirmed compatibility regression; no real Apple/team signed acceptance has been performed.

## Closed selection and retained proof

Use one private `HelperLocation` enum with exactly `LocalStandalone` and `SignedBundled`. Select it only from the already validated, canonical pinned Manager requirement. Include it in `RuntimeGeneration` equality and retain that generation with the authenticated connection. The enum maps only to these compiled absolute paths:

| Mode | Helper |
| --- | --- |
| LocalStandalone | `/Library/PrivilegedHelperTools/openrdx-hardware` |
| SignedBundled | `/Applications/OpenRDXManager.app/Contents/Library/LaunchServices/openrdx-hardware` |

Local capture continues to require administrator enrollment, the complete protected local inventory and verification that standalone helper bytes match its bundled inventory entry. Signed capture requires the bundled helper entry in the complete protected signed inventory and preserves the existing bracketed token-bound Apple/team code proof. It has no dependency on a standalone helper. Inventory hashes or placeholder cdhash fields never replace signed code authentication.

Before launch, `current_exe()` must equal the fixed path selected by that retained generation. Private Rust dispatch calls one of two fixed C wrappers; each wrapper has only the verified peer and output record parameters and uses its own compiled target. The common C implementation remains private, verifies its actual current executable against that fixed target, and retains the existing clean environment, fixed worker argument, close-default descriptors and bounded owned-child contract. No public or caller-selected path, UID, argv, environment or mode selector is introduced.

Final fresh peer/generation proof before ACK must compare the same retained location. A mode change, wrong current executable, stale inventory, unavailable selected helper or rejected launch refuses. Never try the other helper or direct authority as fallback. Direct-process CLI policy from Task 5 remains separate and unchanged.

## Regression evidence and review gates

1. Record a behavioral RED showing that signed capture unnecessarily consults standalone verification; exercise the same selection/verification helper consumed by production, with verifier injection confined to unit tests.
2. Require signed mode with no standalone dependency, required bundled inventory entry, and local mode still enforcing standalone byte verification. Missing bundled entry, wrong canonical requirement and changed mode must refuse.
3. Exercise the consumed current-executable predicate for both exact paths and both cross-mode mismatches. Check generation equality includes location and fresh revalidation cannot switch modes.
4. Verify both production C wrappers target their own compiled helper and reject current-executable mismatch, with fixed argv/environment and no fallback. Test-only harmless targets remain absent from production ABI/build.
5. Cross-check helper constants against signed plist, native client and local installer layout. Re-run focused child tests, strict native compilation, affected Node contracts, both Rust feature modes and formatting. Freeze source and evidence for independent review before integration.

Host selection, fixture and source checks prove this compatibility contract, not real signed installation or device acceptance. The intended unsigned locally enrolled package still requires installed authentication and selected dock verification; actual Apple/team signed acceptance remains explicitly untested.
