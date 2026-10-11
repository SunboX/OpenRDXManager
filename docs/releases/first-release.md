<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

The first OpenRDXManager release provides a desktop companion for [OpenRDX](https://github.com/SunboX/OpenRDX), with dock and cartridge information, diagnostics, media tools, guided firmware workflows, manufacturing backups, local help and AI integration.

Download the installer matching your operating system and processor:

- **macOS:** DMG or ZIP, for Apple silicon (ARM64) or Intel (x64).
- **Windows:** installer EXE or portable ZIP, for ARM64 or x64.
- **Linux:** DEB, AppImage or TAR.GZ, for ARM64 or x64. The DEB also installs the native service resources; add your intended desktop user to the `openrdx` group and sign out/in before device access.

All packages include the matching native helper and platform addons. `SHA256SUMS.txt` contains the SHA-256 checksum of every installer.

### First-release limitations

These installers are unsigned; macOS apps have an ad-hoc signature and are not notarized. Operating-system trust prompts may apply. **The privileged macOS and Windows service paths require a trusted signed Manager, so device access through those installed services remains unavailable in these unsigned packages.** Their signature and authorization checks remain enforced. Installing an app or seeing its window does not prove that it can access your dock.

Linux DEB installation configures the existing systemd socket, device rule and policy without automatically granting group membership to users. AppImage, ZIP and TAR.GZ packages do not install system services. See the [installation guide](https://github.com/SunboX/OpenRDXManager/blob/main/docs/installation.md) for setup and platform limits.

Automated builds and packaged-app launch checks cover software behavior on each native platform. This release does not add physical RDX hardware validation. Firmware updates and first installation of OpenRDX remain limited to the supported device, firmware and platform combinations in the [migration guide](https://github.com/SunboX/OpenRDXManager/blob/main/docs/migration.md).

Software: AGPL-3.0-or-later. Documentation and owned media: CC-BY-SA-4.0. Third-party notices are included with the application and in the source repository.
