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

Branch and pull-request builds upload artifacts without publishing. The collection job requires all fourteen installer filenames for the manifest version, checks regular nonempty files, rejects stale versions and generates `SHA256SUMS.txt`. A separate publication job runs only for version tags or manual dispatch with `publish_release=true`. It rechecks the collection, creates a draft with all assets and publishes only after that complete upload succeeds. An existing release is never silently overwritten.

The initial release can be dispatched from the validated main commit:

```sh
gh workflow run build-installers.yml --ref main -f publish_release=true
```

Future version tags must match `v` plus the package version. Source changes are pushed before the build; the release tag points to the exact successful workflow commit.

## Signing and hardware scope

The installers use unsigned/ad-hoc packages with administrator-approved local trust for the Windows and macOS hardware services. A purchased public signing certificate is not required for that mode. The installed app and service still authenticate each other; signature-based distributions require their separate signing credentials. See [installation](../installation.md) and [locally trusted installer notes](../releases/locally-trusted-installers.md).

Software build, installed authentication and physical dock acceptance remain separate results. The Windows EXE acceptance step and its `--installed --require-service` check are mandatory; the release workflow does not normalize their failures. A packaged launch without device access cannot substitute for those checks or prove hardware compatibility.

## Experimental Windows diagnostics

The [Windows token diagnostics workflow](../../.github/workflows/windows-token-diagnostics.yml) owns the restricted-token observations, private child fixtures, source/ACL/debugger controls and read-only startup error observer. It runs separately on Windows x64 and ARM64 for relevant diagnostic-source changes or manual dispatch. These launch experiments are compiled only into tests and are not the installed Manager’s launch path.

The original native commands, failure exits, ownership/cleanup rules, deadlines and closed three-day diagnostic artifacts remain unchanged. A failed owned medium child still fails that diagnostics job. Diagnostic results do not establish production authorization or successful startup, and this workflow cannot publish releases. Installer collection and publication depend on the six production build/acceptance jobs, not on this research workflow. The separation was explicitly selected by the user on 2026-10-16; it is not a claim that the experimental DLL-initialization failure was fixed.
