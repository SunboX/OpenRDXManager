<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows media insertion — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

The connected Windows receiver runs OpenRDX 1.10. This investigation concerns
Manager discovery and presentation; it performs no firmware write or cartridge
format.

## Observed failure

At 12:57:09 UTC, inserting a cartridge caused a `service-malformed-data` recovery
and service restart. Manager subsequently showed the cartridge as Good. The user
reproduced the brief disappearance after a normal safe eject and reinsertion.

A private, read-only tap on the application's existing framed decoder captured
the second failure. Discovery last completed at 13:01:02.623 UTC; the next scan
completed at 13:01:27.769 UTC, after roughly 25 seconds. The inserted-media event
passed the production schema and was accepted. Its late scan acknowledgement was
also accepted. At 13:01:27.774 UTC a valid device-list response arrived for a
request whose deadline had expired. The unknown correlation triggered recovery
at 13:01:27.776 UTC. The cartridge data itself was valid.

Evidence remains outside Git in `native-windows-20261008-1/media-before-fix.jsonl`
and `media-insertion-investigation.json`. Device identifiers and raw status
frames are private evidence.

## Correction

`src/main/expired-discovery-requests.mjs` retains at most 64 exact expired
discovery correlations per service generation. One valid late scan or list reply
is consumed without applying its stale result. The history clears on stop,
restart, and fault. Unknown, duplicate, evicted, previous-generation, and malformed
replies remain protocol failures. Operation timeouts retain their existing
outcome-unknown behavior and cannot enter this discovery history.

The same policy applies while the inbound control lane waits for an operation's
terminal acknowledgement. It preserves terminal publication order.

The renderer also distinguishes a nonempty inventory with no selection from an
empty inventory. It offers explicit selection after a selected dock departs and
returns, preserving the rule against silently retargeting operations.

## Verification

The synthetic insertion regression failed before the correction and passes
after it. The focused protocol/discovery/operation set passed 167 tests; the
expanded FIFO control-lane suite passed 14. Tests include stale-list rollback,
duplicate and malformed replies, generation reset, bounded eviction, and a late
discovery reply crossing a held terminal without reordering publication.

`npm test`, including its preload and native build hooks, completed with 919
tests: 907 passed, 8 skipped, and 4 failures in the existing Windows visual-QA
checks. Those failures concern missing raster anchors and the resulting absent
baseline capture; the full suite is not green. The native cross-process build
and generation restart check passed after Manager was fully closed.

`npm run smoke` passed after rebuilding the runtime. Its unprivileged app profile
reported `event-log-unavailable`; this proves the mounted renderer and truthful
unavailable state, not privileged hardware access. Formatting and focused diff
checks passed.

The corrected application reopened at 13:15:59 UTC using the normal secured
Windows profile and production preload bridge. Its inventory reported `ready`,
`privileged: true`, and `hardwareReady: true`, with the inserted 3 TB cartridge
reported as Good. The actual window shows that cartridge's capacity and status.
Sandbox and context isolation remain enabled; Node integration remains disabled.
Private evidence: `manager-running.json` and `manager-running.png` from that time.

The user completed a normal safe eject and reinsertion with the corrected
application. Eject completed at 13:18:38.653 UTC. During reinsertion, the scan
request expired at 13:19:18.489 UTC and the subsequent device-list request expired
at 13:19:23.498 UTC. The inserted cartridge event was accepted at 13:19:26.844 UTC,
and both exact late replies were consumed at 13:19:26.847–849 UTC. The capture
contains one service handshake throughout; there was no service restart. The
user confirmed that Manager stayed connected and displayed the cartridge.

Private evidence: `media-protocol-capture.jsonl` and
`media-fixed-cycle-result.json`. This verifies one physical cartridge insertion
cycle on the connected Windows receiver. It does not qualify other cartridges,
filesystems, receivers, or platforms.
