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

As requested on 2026-10-19, publication no longer requires manual Windows x64/ARM64 VM acceptance receipts. Build installers still requires all six native platform/architecture jobs, fatal formatting and native/security/application tests, packaged checks, macOS PKG acceptance and Linux DEB acceptance. The collection requires all sixteen installers for the manifest version and generates `SHA256SUMS.txt`. Build, pull-request and tag events cannot publish a release.

[Publish verified release](../../.github/workflows/publish-verified-release.yml) is a separate main-only manual workflow. Select a completed successful main-branch Build installers run from this repository, triggered by push or manual dispatch. Authenticated GitHub metadata must match the repository, run ID, attempt, commit and exact workflow path before artifact download. Trusted gate code runs from the workflow checkout; the selected candidate checkout supplies only package.json and release notes and is never executed.

The gate verifies every expected installer, rejects linked/hard-linked, empty, missing and unexpected installer files, and checks the collected checksum file without rewriting it. It retains a closed candidate record binding the source commit, run attempt, version, sizes and all seventeen asset digests. A changed attempt or asset fails re-verification. Verification artifacts are retained for three days.

To verify without publishing:

```sh
gh workflow run publish-verified-release.yml --ref main -f build_run_id=123456789 -f publish_release=false
```

After reviewing verification and any requested installed-device checks, dispatch with `publish_release=true` to authorize the write-scoped publication job. That job downloads the exact verified inputs, refreshes authenticated run metadata and repeats the gate against the retained candidate. The publisher also validates the candidate before its first GitHub call.

Publication refuses existing drafts/published releases and conflicting tags. It creates a missing non-overwriting tag at the exact verified commit, uploads only the sixteen explicit installer paths and SHA256SUMS.txt into a new draft, and checks names, sizes and GitHub server SHA-256 digests before making it public. It publishes by verified numeric release ID and checks the tag, target and all assets again afterward. Interrupted uploads can leave a partial draft for deliberate inspection; nothing overwrites or automatically resumes it. GitHub provides no atomic tag-compare-and-publish operation against concurrent authorized writers.

Manual Windows installer acceptance remains available through scripts/verify-windows-installation.ps1 on a disposable machine. It is optional diagnostic coverage, not a mandatory receipt or a claim of ARM64 installed authentication. An installed x64 service check proves only that selected installation; builds, installed authentication and physical dock behavior remain distinct evidence.

## Signing and hardware scope

The installers use unsigned/ad-hoc packages with administrator-approved local trust for the Windows and macOS hardware services. A purchased public signing certificate is not required for that mode. The installed app and service still authenticate each other; signature-based distributions require their separate signing credentials. See [installation](../installation.md) and [locally trusted installer notes](../releases/locally-trusted-installers.md).

Software build, installed authentication and physical dock acceptance remain separate results. The local Windows EXE acceptance suite and its `--installed --require-service` check remain available for explicit installation verification. Publication does not require manual VM receipts. A packaged launch without device access cannot substitute for those checks or prove hardware compatibility.

## Experimental Windows diagnostics

The [Windows token diagnostics workflow](../../.github/workflows/windows-token-diagnostics.yml) owns the restricted-token observations, private child fixtures, source/ACL/debugger controls and read-only startup error observer. It runs separately on Windows x64 and ARM64 for relevant diagnostic-source changes or manual dispatch. These launch experiments are compiled only into tests and are not the installed Manager’s launch path.

The original native commands, failure exits, ownership/cleanup rules, deadlines and closed three-day diagnostic artifacts remain unchanged. A failed owned medium child still fails that diagnostics job. Diagnostic results do not establish production authorization or successful startup, and this workflow cannot publish releases. Installer collection depends on the six production build jobs; publication additionally requires successful exact-candidate verification. The research workflow is not a publication dependency. The separation was explicitly selected by the user on 2026-10-16; it is not a claim that the experimental DLL-initialization failure was fixed.
