<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Event logging

## Overview

**Tools > Event Logging** toggles operation logging. A check mark indicates
that it is enabled. The documented Windows path is:

```text
C:\Windows\LogsOverlandTandberg\_RDXManager.txt
```

The log records Manager operations and failures for support diagnosis. Each
time RDX Manager starts, it creates a new current log and renames the previous
one `_RDXManager.bak`; rotation therefore keeps a current and previous file.

## Implementation overview

The executables contain a logging subsystem and formatter used by UI actions,
device operations and error paths. Messages surrounding self-test, firmware,
eject, drive-letter, formatting and protection actions feed the same log.
Windows administrative access is required because the target directory is
under `C:\Windows`.

This feature is separate from drive firmware logging: it writes host-side text
and does not send a special logging CDB. Device errors included in it originate
from the normal SCSI command result and decoded sense data.

## Expected results

- Enabled: new operations append to `_RDXManager.txt`.
- Disabled: the Manager stops adding events; existing files remain.
- Restart rotation: previous content is renamed to `_RDXManager.bak` and a new
  `_RDXManager.txt` is created.
- Failure to create/write the directory: operations can continue, but host
  diagnostic recording is unavailable.

## Implementation details

The GUI action changes a host-side logger flag. Operation controllers emit
formatted start, success, failure, transport result and decoded-sense messages
through the same logger, so the log captures both user actions and lower-level
device failures. The Windows target directory requires administrative write
access. Rotation renames the current file to `_RDXManager.bak` and opens a
fresh `_RDXManager.txt`.

The log is independent of controller flash and of LOG SENSE pages: disabling
it does not disable drive error counters, SMART data, or Windows Event Log.

## Protocol details

There is no Event Logging SCSI CDB. Its input protocol is an in-process stream
of Manager operation records:

```text
UI/test operation -> command result + sense/OS error -> formatter
                  -> append UTF-8/ANSI text -> optional rotate to .bak
```

When a SCSI operation is logged, the status follows the shared transport
contract: result `0` clean, `3` host pass-through failure, `4` SCSI/sense
failure. The logger records the outcome but never changes or retries the
command itself. The documented file path and toggle behavior come from manual
page 12; the string reference for Windows Manager 2.0.1.54 provides
additional implementation evidence.

## PDF-derived operational and release details

The manual recommends enabling Event Logging when operations are failing and
the user needs a diagnostic record for Technical Support. The check mark next
to **Tools > Event Logging** is the authoritative UI indication that logging is
enabled. Disabling logging does not delete the current or backup file.

OpenRDXManager treats that toggle as the optional diagnostic-activity setting.
When disabled, ordinary queued, started, and progress activity is suppressed,
while bounded redacted configuration changes and ready/terminal lifecycle audit
records still use the mandatory persistence lane. The toggle change itself is
persisted before the new setting takes effect. This is an OpenRDXManager safety
invariant, not a claim about an additional vendor file format.

Windows releases 0.1.0.25 and 0.1.0.30 both describe RDXmon/event-logging
improvements, but do not publish a new file format or record schema. They are
therefore compatibility history rather than evidence of another device
command. The exact restart filenames stated by the manual are:

```text
C:\Windows\LogsOverlandTandberg\_RDXManager.txt
C:\Windows\LogsOverlandTandberg\_RDXManager.bak
```

Source coverage: Product Manual p. 12; Windows 2.0.1 Release Notes pp. 2-3.
