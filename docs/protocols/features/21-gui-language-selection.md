<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# GUI language selection

## Overview

The Manager bundles Qt translations and can select the GUI language from the
command line:

```text
RDXManager.exe -l xx
```

Documented language codes are:

| Code | Language   |
| ---- | ---------- |
| `en` | English    |
| `zh` | Chinese    |
| `de` | German     |
| `fr` | French     |
| `it` | Italian    |
| `pt` | Portuguese |
| `es` | Spanish    |
| `ja` | Japanese   |

## Implementation overview

At startup Qt parses `-l`, loads the matching bundled translation resource and
installs it before constructing the UI. Language selection changes Manager
labels/dialogs only; it sends no drive command and changes no cartridge data.

If a code/resource is unavailable, the build falls back to its default
language rather than making the device unusable. The accepted code list and
syntax are documented by the bundled manual and corroborated by translation
resources/strings in the installer.

## Implementation details

Argument parsing occurs before the main Qt widgets are constructed. The code
maps the two-letter code to a bundled Qt `.qm` translation resource, loads it
with `QTranslator`, installs it on the application, then creates dialogs and
menus so their `tr()` lookups use the selected catalog. Qt's own standard
dialog translations are loaded alongside the Manager catalog where bundled.

The language is process-local startup state. It does not rewrite the firmware,
registry drive configuration, cartridge or installer payload.

## Protocol details

The complete external interface is:

```text
RDXManager.exe -l <en|zh|de|fr|it|pt|es|ja>
```

This is command-line/Qt resource selection only. No SCSI, service IPC or
network request is needed. Missing/invalid catalogs fall back to the compiled
default strings. Success is observable by translated UI text after startup;
there is no numeric device return value.

Evidence anchors: bundled translation resources under
`analysis/extracted/payloads/windows-2.0.1.54/` and the command-line language
section of the bundled manual.

## PDF-derived language history and exact bundle evidence

The manual explicitly prints command-line codes for English, Chinese, German,
French, Italian, Portuguese and Spanish, and shows that the language argument
can also be placed in a Windows shortcut target. Windows release 0.1.0.28
introduced the six non-English languages in that list. Release 0.1.0.30 added
Japanese; 0.1.0.33 updated its translation and fixed firmware updating when the
GUI was configured for Japanese.

The supplied 2.0.1.54 payload contains `Rdx_Manager_ja_JP.qm`, `fervor_ja.qm`
and Qt's `qt_ja.qm`, confirming that Japanese resources remain bundled. The
two-letter `ja` form follows the same Qt locale/resource convention; unlike
the other seven codes, it is corroborated by payload and release-note evidence
rather than printed in the supplied Rev F manual's CLI list.

Source coverage: Product Manual pp. 37-38; Windows 2.0.1 Release Notes pp. 2-3.
