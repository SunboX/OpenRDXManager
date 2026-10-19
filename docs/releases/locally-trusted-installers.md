<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

Version 1.0.2 fixes Windows service connection startup on machines where complete installed-runtime verification takes longer than eight seconds. Client verification and service preparation have their own bounded allowances around peer proof. The service also recovers its listening pipe when an early client disconnects before acceptance. Installed macOS service startup allows time for independent server-side identity checks before the handshake reply, including on Intel machines. Installed authentication verification uses matching outer watchdogs. Runtime integrity, service identity and device access checks remain required.

Windows and macOS installers now include an administrator-approved local installation mode for the hardware service. A public signing certificate is not required for this mode. The app and service still authenticate each other, and editing installed application files disables device access until an administrator runs the installer again.

Choose the package matching your operating system and processor:

- **macOS:** PKG, also supplied inside the DMG, for Apple silicon (ARM64) or Intel (x64). Run the installer and open the installed app from Applications. The ZIP is a portable app without hardware-service setup.
- **Windows:** EXE installer for ARM64 or x64. Connect the RDX dock during setup. After setup finishes, click **Retry service** if the app still shows a service error. Unplug and reconnect the dock after first-time setup, then scan again if needed. Keep a virtual machine’s dock assigned to that same virtual machine. The ZIP is a portable app without hardware-service setup.
- **Linux:** DEB, AppImage or TAR.GZ for ARM64 or x64. The DEB supplies the system service; an administrator must add the intended desktop user to the `openrdx` group and the user must sign out/in.

Unsigned-download warnings may remain. Approve only an installer from a source you trust. Local installation does not add a certificate authority to the computer. `SHA256SUMS.txt` lists all installer checksums.

Finish active device operations and close Manager before updating, repairing or removing it. On Windows, a newly attached or recreated device instance may require another installer run with the dock connected. Device access remains subject to supported dock identity, firmware, drivers and cartridge state; software authentication checks do not establish physical hardware compatibility.

See the [installation guide](https://github.com/SunboX/OpenRDXManager/blob/main/docs/installation.md) and [migration guide](https://github.com/SunboX/OpenRDXManager/blob/main/docs/migration.md). Software is AGPL-3.0-or-later; documentation and owned media are CC-BY-SA-4.0.
