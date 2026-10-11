<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Write/Read Test

## Overview

Write/Read Test verifies the complete host filesystem path rather than only
SCSI command transport. It writes a test file to the mounted cartridge, reads
it back, compares the content and removes the file.

The test requires inserted, formatted, writable media with enough free space
and enabled/authenticated data access. Read-only/write-protected media cannot
complete the write phase.

## Internal flow

```text
validate selected mounted RDX volume
    -> create/open test file
    -> generate/write test data
    -> flush/close
    -> reopen/read
    -> compare expected and received bytes
    -> delete temporary file
```

This is deliberately host filesystem I/O; it does not send a special RDX
diagnostic CDB. Normal block requests are produced by the operating system and
drive stack. The Manager reports pass only if write, read and comparison all
succeed. Cleanup is attempted on failures so diagnostic data is not left on
the user's cartridge.

The bundled manual describes the prerequisites and objective; executable
messages provide the pass/fail path. The exact test filename, byte pattern and
file size are not asserted because they have not been isolated from this build.

## Implementation details

The test resolves the selected dock's mounted volume path and validates media,
write access and free space before creating a temporary file. It uses normal
Windows file APIs through the mounted filesystem, flushes/closes before
reopening, compares the returned bytes with the generated buffer and deletes
the file. An error in create, write, flush, reopen, read, compare or cleanup is
reported in the test/log path.

This deliberately covers layers that SEND DIAGNOSTIC does not: filesystem,
filter/mount stack, partition, block driver, USB/SATA transport, cartridge HDD
and the return path.

## Protocol details

There is no Manager-issued diagnostic CDB. The protocol boundary is the host
filesystem API:

```text
CreateFile -> WriteFile -> FlushFileBuffers/close
           -> CreateFile/read -> compare -> DeleteFile
```

Windows translates this into ordinary SCSI block traffic (READ/WRITE commands
appropriate to the volume stack), but their LBA/count segmentation is chosen
by the OS cache/storage driver and is not fixed by RDX Manager. Therefore a
packet capture will vary by filesystem, cache policy and test size. Manager
pass means exact byte comparison plus successful file operations, not merely
SCSI GOOD on one request.

## PDF-derived prerequisites and result presentation

The manual explicitly requires a properly formatted inserted cartridge, some
free space, and the physical write-protect switch in the OFF position. A
read-only authentication credential is an equivalent write blocker even when
the tab itself is not physically locked. The temporary file is deleted after
the comparison completes.

The shared Test-tab progress bar advances during the filesystem operation. It
turns green and shows a success message only when the write, read and compare
stages pass; on failure it stays blank/gray and shows a failure message. The
troubleshooting appendix says a write failure should first be checked against
the physical write-protect tab and use of a read-only encryption password.

Source coverage: Product Manual pp. 30-31 and 36.
