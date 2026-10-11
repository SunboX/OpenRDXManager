<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Installer release implementation plan

**Goal:** Build all desktop installers in GitHub Actions and publish v1.0.0 only after every target passes.

**Architecture:** Six native runners build the Electron application, matching Rust helper and N-API addons. A collection job validates fourteen installers and generates checksums before creating a draft release, uploading its complete asset set and publishing it.

**Constraints:** package.json owns the application version. Preserve privileged-service authentication and Electron isolation. Match the reference project's unsigned/ad-hoc builds; describe the signing and hardware-validation limits. No vendor installers, local analysis, credentials or build caches enter the app package.

- [x] Add focused failing tests for platform resources, complete installer collection, missing/empty/stale artifacts and checksums.
- [x] Add `scripts/installer-config.mjs`, `scripts/prepare-installer-runtime.mjs`, `scripts/release-assets.mjs`, installer resources and npm distribution commands. Verify the tests and locally package the macOS app.
- [ ] Correct the existing visual QA failure without relaxing assertions. Run format, Node, native and Electron checks.
- [x] Add `.github/workflows/build-installers.yml` with native macOS/Windows/Linux x64 and ARM64 builds, artifacts, collection and gated release publication. Validate its YAML and test its asset gate.
- [ ] Update installation and release documentation, review the explicit Git diff, commit and push the required changes.
- [ ] Run the workflow on the exact commit. Inspect each failure, fix its cause and rerun. Verify the fourteen assets and published release metadata before reporting completion.
