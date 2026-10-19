<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Release acceptance and optional Windows diagnostics

The user replaced the manual VM receipt requirement on 2026-10-19 because Windows x64 and ARM64 acceptance VMs are unavailable. Publication no longer requires those machines or operator attestations.

## Required automated evidence

The selected Build installers run must be a completed successful push or manual run from this repository's main branch and exact workflow path. All six native platform/architecture builds and their fatal existing tests remain required. The collection supplies all sixteen version-matched installers and SHA256SUMS.txt.

The main-only manual publication workflow validates authenticated metadata before download. It reads only the candidate manifest and release notes from the selected source commit. Candidate code is never executed by the gate. Verification checks regular single-link files, every expected asset and the exact collected checksums without regenerating them.

The retained candidate record binds schemaVersion=1, repository, runId, runAttempt, sourceCommit, version, sixteen installer names and seventeen asset size/SHA-256 pairs including SHA256SUMS.txt. Re-verification requires exact equality, including source and attempt. A refreshed successful run cannot silently replace the verified candidate.

Only explicit publish_release=true enables the write-scoped publication job. It repeats candidate verification before invoking the publisher. Existing releases, conflicting tags, partial or changed assets, and mismatched uploaded server digests fail publication. These requirements replace the earlier windows_acceptance workflow input; no placeholder or fabricated VM receipt is accepted or needed.

## Optional installed verification

scripts/verify-windows-installation.ps1 and the legacy receipt parser remain available for deliberate diagnostics on disposable Windows machines. They do not gate publication. Existing helper authentication, token, ACL, ownership, cleanup and rejection checks are unchanged.

For an existing installation, `npm run verify:packaged-app -- --installed --require-service` checks actual installed application/service authentication and the external MCP bridge. It does not prove physical device operations, clean installation, upgrade/removal coverage or installed ARM64 behavior. Report which architecture and machine were actually checked.

See [installer builds and releases](../development/installer-builds.md) for current dispatch commands and publication recovery behavior.
