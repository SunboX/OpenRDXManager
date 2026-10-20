<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

Windows setup now journals and enrolls `SeManageVolumePrivilege` for the fixed `NT SERVICE\OpenRDXHardwareService` identity. The service enables it only on a temporary thread token while opening mutation volume handles, locking or dismounting; metadata discovery does not enable it. Setup also journals, applies and reads back the exact live cartridge volume device DACL: the persistent device registry property alone can leave an already mounted NTFS volume inaccessible to the service. Both are required to address safe-eject failures during Host Unmounting. Setup preserves a pre-existing privilege grant, removal revokes only its own grant, and live volume restoration preserves later administrator changes. Device identity, exact topology, read/write access and exclusive-lock checks remain required.

Windows removal now retains the protected enrollment parent, historical authority and runtime files without retaining a conflicting read lease on the journal directory itself. This allows its atomic restoration journal update to complete during removal or upgrade. Runtime/history replacement and namespace replacement remain refused.

Mounted Windows cartridges now use an independently verified volume-root filesystem query when a metadata-only volume handle does not support that query. This fixes cartridge scans rejected as `candidate-host-facts-failed` while preserving RAW-media and failure checks.

Cartridges inserted after Windows setup no longer need raw volume write access merely to appear in discovery. Read-only metadata queries retain exact disk/volume topology and mount checks; mutating operations keep their existing separately checked read/write volume leases. Windows setup now explicitly explains reconnecting the dock to activate its per-instance permissions.

Version 1.0.3 prevents Windows setup from silently skipping a connected disk advertising an RDX product when its required open or live identity probe fails. Such failures now stop setup with a bounded diagnostic; device permissions still require a complete positive live RDX identity. Installed-device acceptance can require the exact connected dock in the service's validated scan inventory, independently of service authentication and capability flags.

Version 1.0.2 fixes Windows service connection startup on machines where complete installed-runtime verification takes longer than eight seconds. Client verification and service preparation have their own bounded allowances around peer proof. The service also recovers its listening pipe when an early client disconnects before acceptance. Installed macOS service startup allows time for independent server-side identity checks before the handshake reply, including on Intel machines. Installed authentication verification uses matching outer watchdogs. Runtime integrity, service identity and device access checks remain required.

Windows and macOS installers now include an administrator-approved local installation mode for the hardware service. A public signing certificate is not required for this mode. The app and service still authenticate each other, and editing installed application files disables device access until an administrator runs the installer again.

Choose the package matching your operating system and processor:

- **macOS:** PKG, also supplied inside the DMG, for Apple silicon (ARM64) or Intel (x64). Run the installer and open the installed app from Applications. The ZIP is a portable app without hardware-service setup.
- **Windows:** EXE installer for ARM64 or x64. Connect the RDX dock during setup. After setup finishes, click **Retry service** if the app still shows a service error. Unplug and reconnect the dock after first-time setup, then scan again if needed. Keep a virtual machine’s dock assigned to that same virtual machine. The ZIP is a portable app without hardware-service setup.
- **Linux:** DEB, AppImage or TAR.GZ for ARM64 or x64. The DEB supplies the system service; an administrator must add the intended desktop user to the `openrdx` group and the user must sign out/in.

Unsigned-download warnings may remain. Approve only an installer from a source you trust. Local installation does not add a certificate authority to the computer. `SHA256SUMS.txt` lists all installer checksums.

Finish active device operations and close Manager before updating, repairing or removing it. On Windows, a newly attached or recreated device instance may require another installer run with the dock connected. Device access remains subject to supported dock identity, firmware, drivers and cartridge state; software authentication checks do not establish physical hardware compatibility.

See the [installation guide](https://github.com/SunboX/OpenRDXManager/blob/main/docs/installation.md) and [migration guide](https://github.com/SunboX/OpenRDXManager/blob/main/docs/migration.md). Software is AGPL-3.0-or-later; documentation and owned media are CC-BY-SA-4.0.
