<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Installation, launch, exit and uninstallation

## Overview

The Windows installer deploys RDX Manager and its supporting services,
drivers, command-line tools, encryption components, translations and local
help. It supports an interactive wizard and a silent administrative mode.
Manager can then be launched from its installed shortcut/executable, closed
with **File > Exit**, and removed through Windows Programs and Features.

RDX Manager 2.0.1 replaces Windows Manager 2.0.0 and RDX Utility 1.61 and
earlier. The historical download workflow supplied by the manual selects the
Windows or Mac directory on the vendor FTP site, downloads the release-note PDF
and installer ZIP, and retains the chosen download location. Those URLs are
historical evidence and are not assumed to remain online.

## Administrative requirements

The manual requires administrative rights to install, configure, license and
update RDX Manager. On Windows 7/Windows Server 2008 or later it instructs the
operator to log in as Administrator or run the installer through **Run as
administrator**. Silent install also requires an administrative command shell.

The exact documented silent-install form is:

```text
RDXManagerInstaller_2.0.n.nn.exe isSilent=true
```

The actual installer filename must replace the example version and the spacing
must be preserved. No user interaction is expected in this mode.

## Interactive install workflow

The manual's complete wizard sequence is:

1. Open the installer ZIP and double-click the EXE.
2. Continue from Welcome.
3. Accept or select the installation directory.
4. Select the RDX Manager component.
5. Accept the license/EULA.
6. Accept the Start Menu shortcut choice.
7. Confirm installation and wait for completion.
8. Click **Finish**.

The documented executable directory is:

```text
C:\Program Files (x86)\Overland-Tandberg\RDXManager\Manager\
```

The installed taskbar/shortcut icon starts `RDXManager.exe` and opens the Drive
List. **File > Exit** closes the Manager process; closing/exit is also required
before uninstalling.

## Uninstallation workflow and release history

The manual removes Manager through **Control Panel > Programs and Features**:
select RDX Manager, choose **Uninstall/Remove**, confirm twice, and wait for the
progress screen. Windows release 0.1.0.30 improved automatic removal of a
previous RDX Manager/RDX Utility, and 0.1.0.40 further improved uninstall.
Release 0.1.0.28 improved installer-failure messages. Release 0.1.0.30 added
silent installation and updated the EULA.

The initial Windows 0.1.0.22 release established this Manager as the successor
to the older RDX utilities. Its published baseline comprised the redesigned
main screen, the Encryption tab with SATA III hardware encryption and multiple
password/access permissions, integrated help, expanded diagnostic/service
features, online Manager/firmware checking, repartition/format, and remote
media eject. Later releases extended that platform rather than introducing a
separate utility family.

## Implementation details

The supplied Windows package is a Qt Installer Framework bundle with component
metadata and compressed payloads. It installs Manager, Eject/RDXmon pieces,
`RdxCmdLine.exe`, Qt runtime/plugins/translations, OpenSSL, local help, Dokan/
`RDXEncrypt` support and uninstall metadata. Component scripts select normal or
silent UI behavior from `isSilent=true` and coordinate prerequisite/previous-
version removal.

Installer success means the selected files/services/drivers and uninstall
registration were created. A process exit or wizard Finish alone does not
prove every driver/service started; runtime discovery in feature 01 is the
functional check.

## Protocol details

Installation is a host package/service protocol, not a drive protocol:

```text
installer EXE + optional isSilent=true
  -> component selection and license
  -> unpack verified component payloads
  -> install/register files, services, drivers and shortcuts
  -> register uninstaller
```

No RDX SCSI CDB is required merely to install, launch, Exit or uninstall the
application. Device configuration performed after launch uses the per-feature
protocols documented in this directory.

Source coverage: Product Manual pp. 8-12; Windows 2.0.1 Release Notes pp. 1-3.

Bundled sources: [Product Manual](../../../original-inputs/RDX+Manager+Manual+1022447+Rev+F.pdf) and [Windows 2.0.1 Release Notes](../../../original-inputs/RDX+Manager+2.0.1+Release+Notes.pdf).
