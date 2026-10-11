<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

<h1 align="center">OpenRDXManager</h1>

<h2 align="center">Your OpenRDX dock, in one place.</h2>

<p align="center">
  <img src="docs/assets/screenshots/status.png" alt="OpenRDXManager dashboard showing a dock and cartridge with demonstration data" width="1000">
</p>

OpenRDXManager is a desktop companion for **[OpenRDX](https://github.com/SunboX/OpenRDX)**. Check your dock and cartridge, run diagnostics, manage media, and follow guided firmware updates from one application.

It is built primarily for devices running OpenRDX firmware. You can also use its guided installation workflow to install OpenRDX on **supported devices that still run vendor firmware**. Read the [migration guide](docs/migration.md) for supported combinations and installation limits.

## Why OpenRDXManager

| Know your device                                                                    | Manage your media                                            | Keep your dock up to date                                                                                 |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| See dock identity, cartridge capacity, free space, and reported health information. | Safely eject, rename, format, and run supported diagnostics. | Update OpenRDX or prepare a supported first installation while preserving the dock's own factory records. |

The application is available for **macOS, Windows, and Linux**. Features depend on your operating system, dock, firmware, and inserted media. The application explains when an action is unavailable.

## Get started

1. Follow the [installation guide](docs/installation.md).
2. Connect your dock, open OpenRDXManager, and select the intended device.
3. Check **Status**, then choose **Tests** or **Utilities** for the task you need.

See [app usage](docs/app-usage.md) for everyday operation and [troubleshooting](docs/troubleshooting.md) if your dock does not appear.

## Install or update OpenRDX

[OpenRDX](https://github.com/SunboX/OpenRDX) lets supported RDX docks use RDX cartridges and qualifying standard SATA drives. OpenRDXManager provides guided firmware selection, progress, and reconnection instructions.

- **Already using OpenRDX?** Follow the [firmware update guide](docs/firmware-updates.md).
- **Still using vendor firmware?** Follow the [migration guide](docs/migration.md). First installation is limited to the supported dock, firmware, and platform combinations described there.
- **Need to recover an interrupted installation?** Use the saved records for that same physical dock and follow the [recovery procedure](docs/migration.md#recover-an-interrupted-installation).

Firmware installation requires an empty dock and stable power. Keep your saved factory records and follow the application's power-cycle prompts.

![Firmware update workflow with demonstration data](docs/assets/screenshots/firmware-update.png)

## Explore the features

These screenshots show the real application with **demonstration data**. They preview its features; they do not establish compatibility with every device. Unavailable information and actions remain visible in the previews.

### Status and discovery

Select a dock, refresh its status, and inspect the information it reports about the dock and cartridge. Automatic scanning helps find connected devices.

<details>
<summary>Device discovery</summary>

![Device discovery and scanning](docs/assets/screenshots/discovery.png)

</details>

### Cartridge protection

The **Encryption** area shows protection and access information. Some protection actions remain unavailable; check the explanation shown for your device before relying on them.

![Cartridge protection view](docs/assets/screenshots/encryption.png)

<details>
<summary>Credentials, automatic access, and protection reset</summary>

![Cartridge credential management](docs/assets/screenshots/credentials.png)

![Create, change, and remove cartridge credentials](docs/assets/screenshots/credential-actions.png)

![Automatic access controls](docs/assets/screenshots/automatic-access.png)

![Protection removal and reset controls](docs/assets/screenshots/protection-reset.png)

</details>

### Diagnostics

Run supported self-tests and LED checks, or check cartridge file transfers with a write/read test. Progress and results stay attached to the selected device.

![Self-test and LED diagnostic controls](docs/assets/screenshots/diagnostics.png)

<details>
<summary>Write/read test</summary>

![Cartridge write/read test](docs/assets/screenshots/write-read-test.png)

</details>

### Media utilities

Safely eject a cartridge, change its volume name, or prepare a new filesystem. Formatting erases the selected cartridge and requires explicit confirmation. Drive mode, connection mode, and Windows drive-letter settings appear when supported.

![Cartridge formatting and confirmation](docs/assets/screenshots/format.png)

<details>
<summary>Ejection, names, modes, and drive letters</summary>

![Safe and force eject controls alongside fixed and removable drive modes](docs/assets/screenshots/eject.png)

![Volume-name controls](docs/assets/screenshots/volume-label.png)

![SATA connection-mode controls](docs/assets/screenshots/sata-mode.png)

![Windows drive-letter controls](docs/assets/screenshots/drive-letter.png)

</details>

### Factory records and recovery

Save a private backup of the dock's factory records. Where supported, restore a saved backup after confirming the intended device. An interrupted OpenRDX installation can use its saved unit records for recovery. See [manufacturing backup and restore](docs/manufacturing-backup-restore.md).

![Manufacturing-data backup](docs/assets/screenshots/manufacturing-backup.png)

<details>
<summary>Restore, installation recovery, and firmware progress</summary>

![Factory-record restore controls](docs/assets/screenshots/manufacturing-restore.png)

![Saved-record selection for installation recovery](docs/assets/screenshots/migration-recovery.png)

![Firmware operation progress](docs/assets/screenshots/firmware-progress.png)

</details>

### Help and support

Browse built-in help, check feature availability, review activity, and prepare a support summary. Update checks are optional.

![Help and support](docs/assets/screenshots/support.png)

<details>
<summary>Help topics, compatibility, and activity</summary>

![Built-in help topics](docs/assets/screenshots/help.png)

![Compatibility and feature availability](docs/assets/screenshots/compatibility.png)

![Activity log](docs/assets/screenshots/activity-log.png)

</details>

### Languages and AI assistants

Choose English, German, French, Italian, Portuguese, Spanish, Japanese, or Chinese. You can also connect a compatible AI assistant through the application's optional **MCP** settings. See [AI-agent access](docs/ai-agent-access.md).

<details>
<summary>Language selection and AI-agent settings</summary>

![German application interface](docs/assets/screenshots/languages.png)

![Optional AI-agent connection settings](docs/assets/screenshots/ai-agent-access.png)

</details>

## Current availability

OpenRDXManager is under development. Hardware support and feature availability are limited, and some operations remain disabled. A supported workflow on one device does not guarantee the same result on another dock or operating system. Consult the application and the relevant guide before changing firmware or cartridge data.

## Documentation

- [Documentation index](docs/README.md)
- [Installation](docs/installation.md) and [app usage](docs/app-usage.md)
- [Firmware updates](docs/firmware-updates.md) and [OpenRDX migration](docs/migration.md)
- [Manufacturing backup and restore](docs/manufacturing-backup-restore.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Serial utility](docs/serial-utility.md)
- [AI-agent access](docs/ai-agent-access.md)

## License

OpenRDXManager was created by **André Fiedler / SunboX**.

Repository-owned software is licensed under **AGPL-3.0-or-later**. Documentation, screenshots, and other project-owned non-code media are licensed under **CC-BY-SA-4.0**, as identified by the file notices and [licensing metadata](.reuse/dep5). Third-party material retains its own notices and terms.

A separate commercial or proprietary license may be available from the copyright holder. See [LICENSE](LICENSE), [commercial licensing](COMMERCIAL-LICENSE.md), and [attribution and notices](NOTICE).
