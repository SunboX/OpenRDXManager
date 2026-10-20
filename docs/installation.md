<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Installation

OpenRDXManager runs on macOS, Windows and Linux. Opening its window and obtaining device access are separate steps: the native hardware service must be available and authorized before a dock can be managed.

## Launch and device access

Download the matching package from [GitHub Releases](https://github.com/SunboX/OpenRDXManager/releases/latest). Choose ARM64 for Apple silicon or an ARM Windows/Linux computer, and x64 for Intel/AMD computers.

- **macOS:** Run the OpenRDXManager PKG installer, supplied separately and inside the DMG, and approve the administrator prompt. It installs the app in `/Applications/OpenRDXManager.app` and its hardware service. Open that installed app from Applications. The ZIP is portable; copying that app does not install or authorize the hardware service.
- **Windows:** Connect the RDX dock, run the installer EXE and approve the administrator prompt. The installer uses a fixed machine-wide location and configures the hardware service for the connected supported dock. Finish setup, then open the installed app. If it shows **Hardware service unavailable**, click **Retry service**. Click **Scan for devices** if it has not appeared. In a virtual machine, keep the dock assigned to that virtual machine. The ZIP is portable and does not install or authorize the hardware service.
- **Linux:** Install the DEB with your package manager, or use the AppImage/TAR.GZ for a portable app. The DEB installs the native systemd socket and device policy. An administrator must explicitly add the intended desktop user to the `openrdx` group (`sudo usermod -aG openrdx "$USER"`); sign out and back in afterward. Portable packages do not install the system service.

These Windows and macOS installers use administrator-approved local trust and do not require a purchased public signing certificate. They do not add a certificate authority to your computer. Unsigned downloads may still show operating-system warnings: approve only the installer you chose from a trusted source. Read the release notes for the selected version; older packages may not include this installation mode. A successful app launch does not prove service or device access.

1. Connect the RDX dock and launch OpenRDXManager.
2. Follow the service setup guidance shown by the application. macOS local installation guidance refers to the PKG installer; a separately signed distribution may use the macOS Login Items approval flow.
3. Check the service status, then select the dock in the device rail. Use **Scan for RDX devices** if it has not appeared.
4. Check the selected dock's identity and cartridge status before starting an operation.

Available actions depend on the operating system, service privileges, dock firmware and inserted media. An unavailable action includes a reason; a visible application window alone does not establish hardware access.

On Windows, setup grants the volume-maintenance privilege to `NT SERVICE\OpenRDXHardwareService`, not to the shared LocalService account. The service enables it on a temporary thread token for mutation-volume opens, locks and dismounts. This is separate from the dock's device permissions and is needed for safe eject of a mounted cartridge. Setup records the prior grant so removal can preserve existing administrator policy. See [Microsoft's filesystem privilege documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges).

With a cartridge inserted, Windows setup also applies and verifies the service's read/write grant on the exact live volume device. The persistent device-instance registry policy alone does not update an already mounted NTFS volume. Setup journals the original live permissions before changing them; removal restores only a matching installer-owned grant and preserves later administrator changes. Keep the cartridge inserted during Repair so setup can enroll its volume.

Windows setup also applies the journaled grant to the exact live dock device. A firmware revision change can create a new Windows device instance with its default permissions. If firmware transfer completes but reconnect verification fails, keep the dock powered, run Repair with that same dock connected, then scan and check its firmware revision before another update. Repair verifies the dock identity and activates access without a USB disconnect or another firmware transfer.

## Repair and update

Use the installer again to update an installed app. Replacing or editing its files manually can disable hardware access; the app will show installation or repair guidance. Close OpenRDXManager after all device operations have finished before running an update or repair. Keep backups and user settings outside the installation folder.

- **macOS:** If the app asks for installation, run the PKG and open the installed copy from Applications. If it asks for repair, close the app and run the PKG again. Use **Check again** after setup, or reopen the installed app.
- **Windows:** Run the EXE installer again with the RDX dock connected. A newly attached or recreated device instance may require another setup run. A cartridge is not required to set up the dock. If cartridge access remains unavailable after inserting ready media, run setup again with that cartridge inserted. If setup cannot identify a supported dock or establish its access, follow the reported retry guidance; do not run the app as administrator to bypass it.

Installer completion, service readiness and physical device readiness are separate results. A dock appears only after the running service verifies it. An unsupported or inaccessible dock remains unavailable even when installation succeeds.

## Moving from an older installation

An older installation may not have the local trust records required by these installers. Setup deliberately refuses to replace an installation or service it cannot identify as its own.

- **Windows:** If setup reports an existing unverified installation, uninstall the older Manager using its original uninstaller, then run the new EXE. Preserve your backups and user settings outside the installation folder.
- **macOS:** If an older Manager registered its helper through Login Items, use that original app's service controls to unregister it before running the PKG. Close the older app afterward. Do not remove another application's service or change system-folder permissions to work around a refusal.

After migration, open the new installed app and check its service status before managing a dock.

## Run from source

The source checkout needs Node.js 22.12.0 or newer, npm and Rust with Cargo. `.nvmrc` selects Node.js 22.16.0. Run these commands from the project directory:

```sh
nvm install
nvm use
npm ci
npm start
```

On macOS, use the approved Terminal and enter administrator credentials only in its `sudo` prompt. Follow the [macOS development setup](development/macos-hardware-access.md) if the helper cannot start.

Windows source builds also require Microsoft C++ Build Tools matching the selected Node/Rust architecture. Raw-device access needs the required Windows privileges; the development launcher does not request elevation automatically.

Linux mounted-cartridge operations require the system bus and UDisks2. Formatting also needs the native tool for the selected filesystem. See [development dependencies](development/dependencies.md) and the [project requirements](development/runtime-setup.md#requirements).

Continue with [app usage](app-usage.md) or [troubleshooting](troubleshooting.md).
