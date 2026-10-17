<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows local release acceptance

Approved by the user on 2026-10-17: Windows installation and authentication acceptance runs in the isolated local VM; GitHub builds the installers and runs the other automated tests. This changes release orchestration, not application authentication or installer policy.

## Build and publication boundaries

Build installers retains the six native build targets, formatting, native/security tests, PowerShell contract regression, application tests, packaged checks, macOS PKG acceptance and Linux DEB acceptance. Only real Windows EXE installation acceptance moves to the local VM. Every remaining CI verdict is fatal. The collection still requires all sixteen installer files and checksums. Build, branch and tag events cannot publish directly.

Publish verified release is a separate main-branch manual workflow. It selects one completed successful Build installers run from this repository's main branch (push or manual event, never a pull request). The run ID, attempt, exact commit and workflow path are validated before downloading its installers-all artifact. Candidate package version and Windows verifier bytes are read from a separate checkout of that exact build commit; trusted gate code stays at the workflow checkout.

Publication requires both x64 and ARM64 VM reports for these exact EXEs. Missing, failed, old, future-dated, duplicate, malformed or mismatched reports fail closed. No token, SID, ACL, machine account, signing credential or physical-device permission changes are part of this design.

## Report and trust model

A report is a maintainer-reviewed operator attestation, not independent cryptographic proof that a VM executed a test. Only an authorized main-branch workflow dispatcher can submit it; its review actor must match that dispatcher. The report includes schemaVersion=1, version, repository, buildRunId, buildRunAttempt, sourceCommit, verifierSha256, reviewedBy, reviewedAt and exactly two architecture results.

Each result includes architecture, installer basename, installerSha256, completedAt and the exported acceptance evidence (the existing helper report, stdout and stderr). The helper report must identify the same source commit, successful complete acceptance for that architecture and observed child exit, with no failure. The stdout must include the exact full-suite success marker, three installed service-authentication passes, three external MCP passes, three non-elevated worker and selected-Manager observations, copied-Manager rejection and native tamper rejection. Stderr must be empty. The verifier hash must match the candidate commit, and installer hashes must match the downloaded files. Reports are bounded to 64 KiB, at most seven days old, and cannot predate the candidate run's start; future clock skew is limited to five minutes. The selected build attempt is mandatory.

The report must not contain credentials or arbitrary local files. The closed logs emitted by successful acceptance contain no raw identities. Only required report fields are retained in the reviewed workflow artifact. Neither a successful generic packaged launch nor older hashes can substitute for these checks. Hardware verification remains a separate evidence layer.

## Release operation

The manual workflow defaults to verification only. It validates all sixteen assets and the report, then saves the verified inputs as one short-lived workflow artifact. A separate publication job runs only when publish_release=true, downloads those exact inputs and checks them again before any release write. The tag targets the selected build commit. An existing release is never replaced; a conflicting existing tag is refused. Draft creation/upload must finish before the release is made public. Only the sixteen installers and SHA256SUMS.txt are release assets; the reviewed VM report stays in the verification artifact.

## Failure and recovery

A failed local suite preserves its failure evidence and cannot produce an acceptable receipt. A new build, changed EXE, changed verifier or another run attempt requires corresponding new acceptance. A failed build or missing artifact blocks publication. Interrupted release creation may leave a draft; no automatic overwrite or deletion occurs. Operators inspect that draft before recovery. A report mismatch causes no system installation, device operation or release write.

## Implementation contract

`scripts/windows-release-acceptance.mjs` exports `validateBuildRun(run, {repository, runId})`, returning validated `sourceCommit`, `runId`, `runAttempt` and `startedAt`; `verifyWindowsReleaseAcceptance({run, receipt, repository, actor, runId, sourceDirectory, installerDirectory, now})`, returning `sourceCommit`, `version`, exact `installers` and normalized `receipt`; and `evidenceSha256(evidence)`, a SHA-256 over recursively key-sorted JSON evidence. Candidate-run validation requires the exact workflow path `.github/workflows/build-installers.yml`, workflow name `Build installers`, completed/success status, same head repository, main branch, and push/workflow_dispatch event. Decimal run IDs must be safe positive integers.

The exact top-level receipt fields are `schemaVersion`, `version`, `repository`, `buildRunId` (decimal string), `buildRunAttempt` (positive integer), `sourceCommit` (40 lowercase hex), `verifierSha256` (64 lowercase hex), `reviewedBy`, `reviewedAt` (UTC ISO timestamp) and `windows`. Each of the two windows entries has `architecture`, `installer`, `installerSha256`, `completedAt`, `evidenceSha256` and `evidence` with `report`, `stdout`, `stderr`. The helper report carries version=1, sourceCommit, mode, status, phase, completed, failure and childCleanup; its existing `vm` field may be consumed but is omitted from retained normalized evidence. Unknown outer or entry fields are rejected. Evidence hashing is canonical and is recomputed over retained evidence, so private extra fields cannot enter the report. Completed times cannot exceed reviewedAt; review actor equality is case-insensitive for GitHub login semantics.

`scripts/verify-windows-release-acceptance.mjs` has two CLI modes: `metadata <build-run.json>` validates authenticated run metadata using BUILD_RUN_ID and GITHUB_REPOSITORY and writes fixed `source_commit`, `run_id`, `run_attempt` fields to GITHUB_OUTPUT when supplied; `verify <build-run.json> <candidate-source> <installers> <receipt-output>` reads bounded WINDOWS_ACCEPTANCE JSON (or an explicit existing RECEIPT_PATH for re-verification), requires GITHUB_ACTOR, verifies all assets and writes only the normalized receipt. Workflow input is supplied through environment variables, never interpolated into shell source. The trusted gate implementation remains in the workflow checkout; only package.json and scripts/verify-windows-installation.ps1 are read from candidate-source.

The publication job reuses the verification artifact, including authenticated build-run metadata and normalized receipt, reads candidate files from the pinned source checkout, runs the same validator again and only then invokes the publisher. The publisher refuses existing releases and conflicting tags before creating a draft. It uses structured argument arrays/JSON, bounded GitHub CLI execution, and explicit installer/checksum filenames; input JSON is never executed. Publication is allowed only for this main-branch workflow's explicitly requested publish_release=true operation.
