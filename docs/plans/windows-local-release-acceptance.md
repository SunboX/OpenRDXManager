<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows local release acceptance implementation plan

> For agentic workers: use the subagent-driven-development workflow, with focused implementation and independent review. Existing commit/push/build/release authorization remains in force; administrator prompts require the user.

**Goal:** Retain mandatory, exact-artifact Windows acceptance in the local VM while GitHub builds and runs the other automated checks.

**Architecture:** A strict receipt validator binds successful local evidence to one successful six-platform build. A separate main-branch manual publication workflow verifies twice, then publishes only the exact installer inventory.

**Tech stack:** Node.js 22 native ESM and test runner, GitHub Actions, existing PowerShell acceptance and GitHub CLI. No new runtime dependencies.

**Spec:** [Windows local release acceptance](../specs/windows-local-release-acceptance.md).

## Global constraints

- Version remains 1.0.1 from package.json; authentication, token/ACL policy, installer and native deadlines remain unchanged.
- Keep all other GitHub checks fatal; retain the complete sixteen-file collection.
- Receipt validation is a maintainer-reviewed attestation, explicitly not an independent VM execution proof.
- Require exact source, workflow, run, attempt, verifier and both EXE hashes; reject stale/missing/failing/ambiguous input.
- Keep secrets, raw identities and VM-private files out of reports and commits.
- Use the isolated worktree; preserve the original checkout's task-owned verification notes and private evidence.

## Task 1: Strict local acceptance validator and report command

- [x] Write deterministic Node tests for valid input and rejected run, receipt, time, architecture, evidence, symlink and installer-hash cases; observe RED.
- [x] Implement bounded report parsing, candidate-run validation and exact-asset/source/verifier binding in cohesive scripts below 1,000 lines.
- [x] Add CLI modes for candidate metadata output and final verified-input checking; use environment input, never evaluated shell text.
- [x] Verify focused tests, formatting and source diff; independent task review.

## Task 2: CI build/publication split

- [ ] Update workflow-boundary tests first: real EXE acceptance is absent from hosted CI, all other checks are fatal, build cannot publish, manual publication requires receipt validation before writes and repeats validation.
- [ ] Move publication out of build-installers, retain sixteen-artifact collection and all other tests.
- [ ] Add the separate manually dispatched main-branch workflow, separate candidate checkout, read-only verification job and write-scoped publication job.
- [ ] Add a tested publisher that refuses release replacement/conflicting tag, pins the target commit and exposes only exact installer assets.
- [ ] Run workflow and publisher tests, formatting, independent review; update maintained installer documentation.

## Task 3: Integration, exact-candidate VM acceptance and publication

- [ ] Review the whole branch and fix load-bearing findings; run relevant Windows/release test suites and format checks.
- [ ] Commit the scoped implementation, integrate into main, push and verify all six CI jobs and collected artifacts.
- [ ] Download the exact successful candidate; stage reviewed hash-pinned local VM inputs. Preserve original installation and failure snapshots.
- [ ] Run x64 and ARM64 full production acceptance from the clean VM baseline with human UAC approval; save exact-artifact evidence and prepare the reviewed receipt.
- [ ] Dispatch verification-only publication; confirm mismatched/absent receipt tests and actual valid verification.
- [ ] Publish the authorized release only after all gates pass; verify remote version, target commit, sixteen assets and checksums. Record any unresolved hardware limitations distinctly.
