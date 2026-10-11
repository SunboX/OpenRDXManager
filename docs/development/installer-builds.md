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

## Publication gate

Branch and pull-request builds upload artifacts without publishing. The collection job requires all fourteen installer filenames for the manifest version, checks regular nonempty files, rejects stale versions and generates `SHA256SUMS.txt`. A separate publication job runs only for version tags or manual dispatch with `publish_release=true`. It rechecks the collection, creates a draft with all assets and publishes only after that complete upload succeeds. An existing release is never silently overwritten.

The initial release can be dispatched from the validated main commit:

```sh
gh workflow run build-installers.yml --ref main -f publish_release=true
```

Future version tags must match `v` plus the package version. Source changes are pushed before the build; the release tag points to the exact successful workflow commit.

## Signing and hardware scope

The first-release configuration deliberately matches the reference's unsigned/ad-hoc packages. It does not remove privileged-service signature verification. Trusted Developer ID signing/notarization and Windows Authenticode signing need separate credentials and packaging configuration before those installed service paths can grant device access. These are software build and no-device launch checks, not physical dock acceptance.
