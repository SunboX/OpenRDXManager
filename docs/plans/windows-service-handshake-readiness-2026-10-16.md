<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows service handshake readiness

Goal: start the existing first-frame exchange only after the authenticated Windows service can process it.

Evidence: installed fc57b92 passes complete file inventory and fuse verification, but ordinary desktop authentication times out about two seconds after SCM publishes RUNNING. Optimized full runtime verification takes 1.6–1.9 seconds with the portable hash and 0.9–1.7 seconds with Windows CNG on this x64-emulated VM. The service arms its two-second reader before constructing a backend that repeats full runtime verification. RUNNING and client-side server identity proof do not establish backend readiness. The SCM fallback Runner/Other alone does not identify the exact failing operation.

A private ordinary-session Windows pipe control with no client writes confirms identification impersonation, token query, expected-user equality, Identification level, explicit reversion, and subsequent server-to-client delivery. This establishes the prerequisite for a server readiness prelude without a circular wait. It is a platform control, not installed-service acceptance.

## Required invariants

- No changes to token policy, accounts, ACL grants, service identity, runtime inventory, content coverage or hardware authorization.
- No runtime content cache. Windows CNG computes fresh fixed SHA-256 for every file; native failures deny verification.
- Keep native activation seven seconds, outer connection eight seconds and first-frame two seconds. Never reset activation for fragments or retries.
- Retain original fatal Windows CI owned-medium-child gate and all cancellation/resource bounds.
- Selected dock stays attached to the Windows VM; acceptance is read-only. Preserve existing backups and settings.
- Version remains 1.0.1. Do not publish with failed CI or absent installed acceptance.

## Implementation and verification

- [x] Add known-vector, fragmented-input, independent-state and tampering tests for the streaming digest; run on host and real Windows. Use CNG only on Windows, preserve the portable implementation elsewhere and regenerate required Cargo locks.
- [x] Add a deterministic fake-clock regression: backend preparation advances three seconds while the complete first frame is queued; the subsequent two-second frame budget still accepts it. Idle and partial frames must still expire at the same absolute deadline. STOP before publication must emit no prelude.
- [x] Prepare backend within hardware ownership, then arm the reader, check STOP and write exactly `OpenRDX:ready:1\n`. Keep peer/session/file/token/reversion/running authority checks before publication.
- [x] Consume exactly that fixed 16-byte prelude in the native client after server identity verification, before publishing connect. Apply the same absolute activation deadline to each fragment and synchronous completion. Missing, malformed, truncated, late or cancelled input fails closed. No compatibility fallback.
- [x] Extract existing overlapped I/O support into a cohesive header to keep handwritten files under 1,000 lines. Keep original aggregate budgets, exact cancellation and terminal proof, bounded drain and unresolved-operation lifetime retention.
- [x] Run portable prelude parsing tests and actual Windows private-pipe controls for immediate/fragmented, silent/partial/malformed/truncated, deadline and cancellation behavior. Build the real native addon with warnings as errors.
- [x] Run relevant Rust tests, Windows-target Clippy, Node tests, formatting, independent review and focused diff review before committing the source. The candidate installer build and artifact checks are recorded separately.
- [ ] Verify artifact lineage and installed ordinary-session authentication, unchanged backup metadata and selected-dock read-only access after the user installs the verified package. Installer completion alone is not acceptance.
- [ ] Run all installer jobs. Investigate the separate original Windows owned-medium-child startup gate; release only after every required gate passes.

Client and server must be updated together. An old/new pair fails closed rather than accepting an unrecognized stream.
