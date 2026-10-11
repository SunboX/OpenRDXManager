<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Help, About and update checking

## Features

The Help menu provides local help (`F1`), About/version information, system
summary generation and **Check for Updates**. The update check covers both a
newer RDX Manager release and available drive firmware, according to the
bundled manual.

## Implementation overview

The bundle includes the PDF manual and Qt help/UI resources. Network checking
is implemented by `FvUpdater::CheckForUpdates` and Qt Network classes: the
Manager retrieves vendor-hosted version metadata, compares it with the local
application/drive versions, and presents the result. The installer also
contains vendor web/support URLs.

The check only discovers/downloads availability. Applying drive firmware is a
separate, local-file Utility action documented in
[15-firmware-update.md](15-firmware-update.md).

## Results and boundaries

- Newer version: the UI offers the vendor-provided update information/link.
- Current version: the UI reports that no newer applicable version was found.
- Network/TLS/server failure: check fails without changing drive or Manager.
- No drive: Manager-version checking can still work; firmware applicability
  needs a discovered drive/product/firmware revision.

The historical URLs embedded in these installers may no longer be live. Their
presence proves the mechanism used by these versions, not current service
availability.

## Implementation details

`FvUpdater` owns a feed URL, a `QNetworkAccessManager`, the current version and
silent/non-silent policy. `CheckForUpdates(bool)` constructs a
`QNetworkRequest`, performs `QNetworkAccessManager::get`, and consumes the
asynchronous `QNetworkReply`. Silent checks suppress the normal "up to date"
dialog; explicit Help-menu checks use the non-silent path. The local help path
opens the bundled manual/help collection without network access.

Firmware applicability is computed locally from discovered product identity,
current firmware revision and feed metadata. Download/check code is separate
from the Utility firmware writer, so a feed response cannot directly issue a
WRITE BUFFER command.

## Protocol details

The update-check wire protocol is an HTTP(S) GET performed by Qt Network:

```text
configured feed URL -> GET -> HTTP status/reply body
                    -> parse release/version metadata
                    -> compare with local Manager and dock versions
```

Qt exposes network error and HTTP-status attributes through `QNetworkReply`;
only a successful, parseable response advances comparison. There is no SCSI
command for checking the web service. Drive data needed for comparison comes
from INQUIRY/LOG SENSE as described in feature 02. Applying a selected local
image begins the separate WRITE BUFFER protocol in feature 15.

Evidence anchors: `FvUpdater::CheckForUpdates`, `CheckForUpdatesSilent`,
`CheckForUpdatesNotSilent`, and Qt Network imports in the symbol-bearing Mac
binary; the Windows binary retains the same updater method strings.

## PDF-derived menu behavior and troubleshooting use

The complete Help menu described by the manual is:

- **Help (F1)** opens local online help in a separate window;
- **About** shows the installed Manager version and copyright;
- **Check for Updates** checks Manager and applicable dock firmware releases;
- **Support** opens the summary/support workflow described in feature 04.

The troubleshooting appendix recommends **Check for Updates** before other
diagnosis. The Utility chapter says a successful firmware check presents an
available update and download link; the downloaded file must still be selected
locally in **Update Firmware**. Windows release 0.1.0.22 introduced integrated
online help and online checks for both Manager and RDX firmware releases.

The manual and release notes contain historical HTTP/FTP locations. They are
preserved as evidence in the extracted source text, but their present-day
availability is not assumed.

Source coverage: Product Manual pp. 12, 31-32 and 36; Windows 2.0.1 Release
Notes p. 3.
