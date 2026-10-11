<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Documentation screenshots

The root README uses 25 screenshots of the real Electron renderer with synthetic demonstration data. They are feature previews, not connected-device results or hardware acceptance evidence. Every capture retains the application's fixture indicator, unavailable data and capability explanations.

## Regenerate the previews

From the project directory:

```sh
npm run screenshots:docs
```

The separate Electron entry point uses a disposable profile and imports the real application views with bounded fixture APIs. It does not create a native device transport, perform firmware or cartridge writes, open an MCP listener, contact update services, or persist application preferences. Native operations are refused by the fixture delegates. The Windows drive-letter preview uses the Windows renderer option on the capture host; it is not a Windows hardware result.

Images are saved in `docs/assets/screenshots/`. The adjacent `manifest.json` records the scene, visible anchor, viewport, demonstration-data provenance and PNG size. Captures wait for local fonts and painted frames and reject missing anchors or horizontal overflow. This is a documentation capture command; it does not replace `npm run test:visual` or its stricter raster and accessibility assertions.

## Coverage

| Screenshots                                  | Features shown                                                                                                                   |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Status, discovery                            | Device selection, manual scan, automatic scan, dock/cartridge information and capacity                                           |
| Encryption                                   | Protection modes, access state and current availability limits                                                                   |
| Diagnostics, write/read test                 | Self-test, LED test, cartridge file-transfer check                                                                               |
| Firmware update, firmware progress           | Image selection, prerequisites, progress and operation locking                                                                   |
| Eject, volume label, format                  | Safe/force ejection, volume names, filesystem selection and destructive confirmation                                             |
| Eject / drive modes, SATA mode, drive letter | Supported device configuration and Windows drive-letter controls                                                                 |
| Manufacturing backup, manufacturing restore  | Factory-record backup, saved inventory and explicit restore consent                                                              |
| Migration recovery                           | Recovery-mode device and saved unit-record selection                                                                             |
| Help, compatibility, activity log, support   | Help topics, all 25 historical feature groups and current availability, event logs, support summaries and optional update checks |
| Languages, AI-agent access                   | Localized interface and optional MCP connection settings                                                                         |

The external serial utility is documented in the [serial utility guide](../serial-utility.md); it has no separate desktop feature screen.

Return to [development documentation](README.md).
