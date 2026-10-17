<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Installer builds and releases

The [Build installers workflow](../../.github/workflows/build-installers.yml) follows the six-runner matrix in [Neon Meter Host](https://github.com/SunboX/neon-meter-host/blob/main/.github/workflows/build-installers.yml): macOS, Windows and Linux, each built natively for x64 and ARM64. It runs application and native tests, builds the matching Rust service and N-API addons, packages installers and launches the actual packaged app with an isolated profile.

`package.json` is the version source. Distribution commands:

```sh
npm ci
npm run dist -- --mac --arm64
npm run verify:packaged-app
```

Use `--win` or `--linux` on their native hosts and select the host's architecture. Cross-packaging Electron with a native helper for a different architecture is unsupported. On headless Linux, use Xvfb and install Electron's setuid sandbox with its intended root ownership and mode rather than disabling renderer isolation.

Application code, production dependencies, preload, icons and license texts enter the app package. Native helpers remain outside ASAR at the fixed existing resource paths. Vendor inputs, local analysis, tests and build caches are excluded. Linux DEB maintainer scripts install the existing exact systemd, udev and polkit resources; they preserve explicit user membership decisions.

Chinese and Japanese font fallbacks are bundled locally under their OFL license, so portable packages do not require system CJK fonts. The copied MCP client configuration resolves an unpacked Node bridge, its main-process modules and production dependencies; external Node clients cannot read Electron's ASAR archive directly.

Firmware tests use deterministic synthetic containers and a separate fixture RSA identity. The production loader retains its pinned vendor key and rejects those signatures even in fixture-enabled test builds. Native tests require no files from ignored vendor-input or analysis directories.

## Publication gate

Build installers runs the six native targets and retains fatal formatting, native/security tests, the PowerShell installer contract, application tests, packaged checks, macOS PKG acceptance and Linux DEB acceptance. Only real Windows EXE installation and authentication acceptance runs in the isolated local VM. Build, pull-request and tag events cannot publish a release. The collection requires all **sixteen** installers for the manifest version and generates `SHA256SUMS.txt`; a successful build alone does not authorize publication.

[Publish verified release](../../.github/workflows/publish-verified-release.yml) is a separate manual workflow that runs only from `main`. It defaults to verification only. Select a completed successful `Build installers` run from this repository's `main` branch, triggered by a push or manual dispatch. The selected run ID and attempt, source commit, workflow name/path and repository must match authenticated GitHub metadata before artifact download. Trusted gate code stays at the workflow checkout; candidate manifest, Windows verifier and release notes come from a separate checkout pinned to the selected build commit. Candidate code is never executed by this gate.

Run both x64 and ARM64 EXE acceptance suites in the isolated local VM against those exact downloaded files. Review the exported helper reports/stdout/stderr, then prepare the bounded JSON receipt described in the [Windows local release acceptance specification](../specs/windows-local-release-acceptance.md). It must bind the manifest version, repository, run ID and attempt, commit, candidate verifier hash, both installer hashes, review actor and timestamps. The review actor must be the workflow dispatcher. Each suite must complete successfully with observed child exit and all required authentication, external MCP, non-elevated worker/Manager and rejection observations. Empty stderr and complete retained evidence are required. The report is a **maintainer-reviewed operator attestation**, not independent proof that a VM executed the test.

Receipts are limited to 64 KiB, seven days of age, the selected run's start time and five minutes of future clock skew. Unknown outer/result fields, duplicates, missing/failing evidence and mismatched hashes are rejected. Only required normalized evidence is retained; VM identifiers, credentials, raw identities and arbitrary private files must not enter the receipt. A changed EXE, verifier, source build or run attempt requires corresponding new acceptance.

To verify without publishing, supply an already reviewed receipt file as JSON input (the following uses `jq` to encode its contents safely):

```sh
BUILD_RUN_ID=123456789
RECEIPT=/absolute/path/to/reviewed-windows-acceptance.json
jq -n --arg run "$BUILD_RUN_ID" --rawfile acceptance "$RECEIPT" \
    '{build_run_id:$run, windows_acceptance:$acceptance, publish_release:"false"}' |
    gh workflow run publish-verified-release.yml --ref main --json
```

The read-only verification job checks all sixteen installers and both receipts, then retains the installers, checksums, authenticated build metadata and normalized receipt in one exact verification artifact for **three days**. Inspect that workflow result before requesting publication. Explicit `publish_release=true` enables a separate job whose `contents: write` permission is scoped only to that job. It downloads that exact verification artifact, checks out the verified source again, refreshes authenticated build metadata to reject a changed run attempt and repeats the same trusted gate before any release write. Use the same dispatch command with `publish_release:"true"` for the reviewed candidate.

The publisher first runs real acceptance validation, then refuses any existing draft or published release and any conflicting version tag. An absent tag is created through the [non-overwriting Git reference endpoint](https://docs.github.com/en/rest/git/refs#create-a-reference) at the exact verified commit; matching lightweight and bounded annotated tags are accepted. Draft creation uses the CLI’s [`--verify-tag`](https://cli.github.com/manual/gh_release_create) option to require that verified remote tag. Only the sixteen explicit installer paths and `SHA256SUMS.txt` are uploaded; the reviewed receipt is never a release asset. Exact names, count, sizes and server SHA-256 digests, release target and tag commit are checked before making the draft public and checked again afterward. The public write uses the verified numeric release ID, with the API’s typed `draft=false` and string `make_latest=true` fields, rather than looking up another release by tag. REST/control commands have a two-minute deadline; the full draft creation/upload has ten minutes, and each workflow job has twenty minutes. These release-only bounds do not change native or authentication deadlines. Missing server digests or partial uploads fail publication.

Failures can leave a matching tag and/or a partial draft for operator inspection. Nothing automatically deletes, overwrites or resumes an existing release. Resolve that state deliberately before retrying. Repeated checks detect tag/release races around creation and publication, but GitHub provides no atomic tag-compare-and-publish operation against other authorized writers; a concurrent change after a final check may require manual recovery even when the workflow correctly reports failure. Never infer successful publication from draft creation or partial upload.

## Signing and hardware scope

The installers use unsigned/ad-hoc packages with administrator-approved local trust for the Windows and macOS hardware services. A purchased public signing certificate is not required for that mode. The installed app and service still authenticate each other; signature-based distributions require their separate signing credentials. See [installation](../installation.md) and [locally trusted installer notes](../releases/locally-trusted-installers.md).

Software build, installed authentication and physical dock acceptance remain separate results. The local Windows EXE acceptance suite and its `--installed --require-service` check are mandatory; the release gate rejects failing or incomplete evidence. A packaged launch without device access cannot substitute for those checks or prove hardware compatibility.

## Experimental Windows diagnostics

The [Windows token diagnostics workflow](../../.github/workflows/windows-token-diagnostics.yml) owns the restricted-token observations, private child fixtures, source/ACL/debugger controls and read-only startup error observer. It runs separately on Windows x64 and ARM64 for relevant diagnostic-source changes or manual dispatch. These launch experiments are compiled only into tests and are not the installed Manager’s launch path.

The original native commands, failure exits, ownership/cleanup rules, deadlines and closed three-day diagnostic artifacts remain unchanged. A failed owned medium child still fails that diagnostics job. Diagnostic results do not establish production authorization or successful startup, and this workflow cannot publish releases. Installer collection depends on the six production build jobs; publication additionally requires the reviewed local Windows acceptance gate. The research workflow is not a publication dependency. The separation was explicitly selected by the user on 2026-10-16; it is not a claim that the experimental DLL-initialization failure was fixed.
