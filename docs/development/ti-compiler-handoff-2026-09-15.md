<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# TI compiler handoff — 2026-09-15

Historical build handoff, prepared on 2026-09-15. The TI build was completed afterward; this document preserves the original assignment and evidence. It is reference material, not a current instruction to build or operate hardware.

> Historical handoff, superseded after the completed TI build: the embedded
> fixture below incorrectly declared the remaining counter unsigned. Production
> uses signed INT32_T. Double subtraction was real; an unnecessary OUT stall was
> not established. Do not reuse that fixture or causal explanation. The returned
> candidate includes the corrected signed test. See the corrected
> [Windows analysis](../reports/windows-bot-cleanup-fix-2026-09-15.md).

## Assignment and limits

Review the existing BOT cleanup correction, run its regression tests, compile it
with the required TI toolchain, and return a complete, checksum-verified
**development candidate plus a Markdown build report**.

This is a build-and-verification handoff, **not permission to flash hardware**.
Do not run an updater, activate firmware, reset or power-cycle a dock, enter ROM
recovery, change drivers, publish a release, push, or tag. Leave hardware testing
to the original assistant after the user returns with your results.

**The correction fixes a demonstrated secondary USB error-cleanup defect. The
original first-chunk firmware rejection is still unresolved. A successful build
must not be described as fixing that rejection.**

Proceed without clarification when the matching source, pinned template, and
compatible TI compiler are available. If a prerequisite is missing, report the
exact blocker; do not substitute a compiler or weaken firmware validation.

## 1. Identify the repository and preserve evidence

The firmware project is **OpenRDX**, not Electron OpenRDXManager and not an older
similarly named firmware copy.

- Repository origin: [SunboX/OpenRDX](https://github.com/SunboX/OpenRDX.git)
- Source HEAD: **01cc3814664bb6fdbe72ecfd1e9dd3dd52a48e9c**
- Branch at handoff: main.
- Historical Windows-visible firmware checkout:
  `\\mac\Home\Documents\privat\Andrés_Werkstatt\OpenRDX`
- Historical Windows-visible Manager checkout:
  `\\mac\Home\Documents\privat\Andrés_Werkstatt\Complete_OpenRDX\OpenRDXManager`
- From that historical Manager directory, the firmware repository was `../../OpenRDX`.

The current Manager checkout is `Andrés_Werkstatt/OpenRDXManager`, next to
`Andrés_Werkstatt/OpenRDX`. From the current Manager directory use `../OpenRDX`.
Verify the repository origin and required historical revision before reusing any
path or build instruction from this handoff.

Paths may differ on your machine. Locate and verify them, and read the applicable
**AGENTS.md** before changing files. These historical instructions do not replace the current repository rules.

At the handoff, the correction was **uncommitted**. Merely fetching the commit above does not
include it. With the shared checkout, inspect and preserve its current changes.
Otherwise, prepare the exact base commit and apply the patch and new tests
embedded below. Do not silently substitute newer main.

Files belonging to this correction:

1. src/rdx_mount/ums_bot.c
2. tests/test_bot_cleanup.py — new
3. tests/fixtures/bot_cleanup_probe.c — new
4. README.md — explanatory development note

An additional local change was observed in linker/tusb9260_link.cmd: executable
mode 100755 to 100644, with **no content diff**. It is not part of this fix.
Preserve it in the user's checkout; do not absorb it into this patch or change
linker settings.

Use an isolated build copy/worktree containing the verified base plus this
correction. Normal PlatformIO builds **regenerate/replace dist/**. Preserve the
original bundle and logs outside that build destination before building. Never
overwrite the Windows testing assistant's approved image or attempt marker.

Do not bump VERSION or invent a release. The current version is **1.10**; a new
candidate may have the same basename/version but different bytes. Keep it in a
uniquely named candidate directory and identify it by hash and source patch.

## 2. Hardware evidence and unresolved failure

The Windows 11 ARM64 host runs under Parallels. The selected TANDBERG RDX
USB 3 / SATA III dock reports raw revision 0110 (displayed as 1.10), with an empty
cartridge bay. The active Windows storage interface is USBSTOR Bulk-Only
Transport (BOT), not UAS.

A guarded, application-coordinated live test made exactly one WRITE BUFFER
submission, then stopped:

| Field                        | Observed value                                  |
| ---------------------------- | ----------------------------------------------- |
| Operation                    | op:d8b0aed4-e6f3-4b39-a50c-4733c1b5f327         |
| First CDB                    | 3B040000000000100000                            |
| Framing                      | 10 bytes; mode 4, buffer 0, offset 0            |
| Requested data-out           | 4,096 bytes                                     |
| SCSI status                  | 02 / CHECK CONDITION                            |
| Fixed-format sense           | key 05, ASC 24, ASCQ 00; no valid field pointer |
| Host-reported completed data | 0 bytes                                         |
| Application error            | firmware-command-invalid                        |

No second chunk, automatic retry, or mode-5 activation was submitted.
A terminal lifecycle event named firmware-readback was cleanup, not proof of
successful transfer or activation.

This proves the command at the observed Windows SPTI boundary, **not** its exact
USB CBW framing, device-side received length, or receiver RAM state.

Subsequent read-only verification read all 61,710 SPI boot-region bytes twice.
Both reads matched the approved image exactly: zero differing bytes and a
non-erased boot marker. Stored flash contents are verified; executing RAM and
the original rejection branch were not independently measured.

Approved ORIGINAL image — preserve these reference facts:

| Field                   | Value                                                            |
| ----------------------- | ---------------------------------------------------------------- |
| Container               | dist/OpenRDX-v1-10.bin                                           |
| Container length        | 62,110 bytes                                                     |
| Container SHA-256       | 4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a |
| Boot interval in SPI    | [0, 0xF10E)                                                      |
| Boot slice in container | [0x18C, 0xF29A)                                                  |
| Boot-region length      | 61,710 bytes                                                     |
| Boot-region SHA-256     | abf7a4156b605fbfd62d123543389ea013e9ceb9828e0a1d48f5bb37da1fa5c6 |

These are reference hashes for the original, **not expected hashes for your
modified build**. Calculate new hashes and keep both identities distinct.

## 3. Confirmed defect and exact correction

In usb_hal_isr.c, usb_hal_handle_xfer_complete subtracts completed TRB bytes from
dBytesRemaining, increments dByteCount, clears bXferActive, then calls BOT.
If the resulting SCSI command fails synchronously, ums_bot_xfer_cleanup(TRUE)
used to subtract the same bytes again. The former fixture incorrectly used an unsigned remaining counter. Production
uses signed `INT32_T`; double subtraction was demonstrated, while an
unnecessary OUT stall was not established. The embedded original fixture below
is retained only as historical context and must not be reused.

Restrict the cleanup's OUT accounting/cancellation block to an **active** OUT
transfer. Do not alter initial SCSI validation, authentication, mutation
interlocks, chunk size, CDB framing, sense interpretation, or activation.

Apply only within ums_bot_xfer_cleanup if not already present:

```diff
diff --git a/src/rdx_mount/ums_bot.c b/src/rdx_mount/ums_bot.c
--- a/src/rdx_mount/ums_bot.c
+++ b/src/rdx_mount/ums_bot.c
@@ -211,8 +211,12 @@ void ums_bot_xfer_cleanup(BOOLEAN_T stall_active_endpt)

     DEBUG("-> ums_bot_xfer_cleanup() - stall = %u.\n", stall_active_endpt);

-    if (gBOT_state == UMS_BOT_STATE_DATA_OUT)
+    if ((gBOT_state == UMS_BOT_STATE_DATA_OUT) && pEP->bXferActive)
     {
+        /* The USB completion handler accounts these bytes and clears
+         * bXferActive before calling BOT. A synchronous SCSI rejection from
+         * that callback must not subtract the same TRB bytes again or stall
+         * an already completed OUT transfer. */
         // Calculate bytes remaining to determine if the OUT transfer is complete.
         pEP->dBytesRemaining -= (pEP->dXferLength - (pEP->pTRB->dStatus & TRB_STATUS_BUFFER_SIZE_MASK));

```

Active partial transfers must still cancel/stall; active fully transferred
requests must still become inactive. Preserve IN cleanup and repeated-cleanup
idempotence. The original rejection happens **before** this cleanup.

The existing README note follows the 1.10 release-notes paragraph:

> Development source now avoids counting completed USB OUT bytes twice when a
> SCSI command fails. The BOT cleanup regression test covers completed, partial,
> active and repeated cleanup. This development correction is not in the existing
> 1.10 release bundle and does not establish the cause of the outstanding Windows
> firmware-command rejection; no newly built or hardware-verified fix is claimed.

After successful TI validation, update this development note accurately for the
candidate, retaining the explicit lack of hardware verification.

## 4. Required toolchain and prerequisites

Read the current AGENTS.md, platformio.ini, scripts/ti_cgt_build.py,
scripts/ti_cgt_tools.py, docs/development/building.md, and the macOS companion
when applicable.

| Host    | Required repository route                                                                                                |
| ------- | ------------------------------------------------------------------------------------------------------------------------ |
| Windows | TI ARM CGT **5.2.5**, normally C:\ti\ti-cgt-arm_5.2.5; armcl.exe and armhex.exe                                          |
| macOS   | Windows TI ARM CGT **5.2.9 through Wine**, normally ~/ti/ti-cgt-arm_5.2.9; existing extensionless armcl/armhex launchers |

Preserve **ti_arm9_abi**, existing optimization/assembler/linker flags, fixed
symbols, section layout, and warnings-as-errors. Do not replace target TI tools
with GCC/Clang or a newer TI version lacking this ABI. Host C compilers are
allowed only for RAM-only tests.

Record actual tool paths/versions, PlatformIO version, host OS/architecture,
and Wine version if applicable. TI_CGT_ROOT may select a verified compatible
installation without changing project defaults. Do not claim cross-host
byte identity without comparing actual artifacts.

On macOS, verify the existing Wine ASCII-drive mapping resolves to the isolated
build directory; old TI tools can fail on accented paths. Preserve mappings
used by other work rather than silently retargeting an active build.

The active build tree is src/rdx_mount/ and include/rdx_mount/, not retained
top-level reference C files. Derive object count from actual inputs: some older
docs say 39 C + 2 assembly; current guidance says 40 C + 2 assembly. Do not
exclude a source to match a stale count.

Packaging requires immutable **RDX2E__STD__F-0283.bin**:

- SHA-256: 73d528801aefc032d3a53637b035f65d72809151b2f127c6b2050e9bacc76f3b
- Available in Manager original-inputs/RDX2E__STD__F-0283.bin.
- Also cached in firmware .pio/rdx-template/RDX2E__STD__F-0283.bin.
- Set OPENRDX_TEMPLATE_PATH to the actual verified template if needed.
- Do not modify the template or run an updater to recover/flash a device.

## 5. Build and verify

Use your configured Python/PlatformIO executables from the isolated firmware
build root. Resolve their locations instead of assuming another account name.

1. Inspect the focused diff and ensure both appended test files exist.
2. Verify the TI compiler version and ABI support.
3. Run the focused test with a host C compiler available. It must run, not skip:
4. Run the full suite.
5. Run the normal PlatformIO build.

```text
python -X utf8 -m unittest discover -s tests -p test_bot_cleanup.py -v
python -X utf8 -m unittest discover -s tests -v
pio run -e tusb9261_ti_cgt
```

Typical executable locations are ~/.platformio/penv/bin/ on macOS and the
installed user's .platformio/penv/Scripts/ on Windows. Configure MSVC
INCLUDE/LIB/PATH for the new host test when cc is unavailable. On Windows set
PYTHONUTF8=1 for Python children as well.

If Git rejects a verified UNC checkout, use a process-scoped safe-directory
setting for that exact path, not a wildcard or global trust expansion.

Inspect complete logs, exit codes, warnings, the map, and the regenerated bundle.
Fix regressions within this narrow correction if necessary, then rerun tests.
Do not suppress diagnostics or alter ABI/linker settings to force success.

A normal successful build automatically refreshes the complete dist/ bundle,
even when compiler outputs were already up to date. Do not stop with only .pio/
updated. No release-publishing entry point is required.

The current package_github_release.py publisher hard-codes Windows 5.2.5
provenance. Do not use it to mislabel a macOS 5.2.9 candidate. Its existing
**read-only validation functions** can be used without publishing:

```python
from pathlib import Path
from scripts.package_github_release import validate_bundle, validate_version

root = Path.cwd()
version = (root / "VERSION").read_text(encoding="ascii").strip()
validate_version(root, version)
bundle = validate_bundle(root / "dist", version)
assert len(bundle) == 6
base = "OpenRDX-v" + version.replace(".", "-")
assert (
    root / ".pio/build/tusb9261_ti_cgt/TUSB9261_RDX_flash.hex"
).read_bytes() == (root / "dist" / (base + "-FlashBurner.hex")).read_bytes()
print("Version, six-file bundle, manifest/checksums, and continuous HEX verified")
```

Inspect the map for unexpected layout/size changes. If compatible instruction listing
tools are already available, also check the compiled cleanup's active-transfer
guard. If the image does not fit, report the exact failure; do not move sections.

A base commit plus an uncommitted correction is **not** the bare commit's source.
Include the complete focused patch, including new files, and its SHA-256.

## 6. Verification already completed here

- Original extracted receiver replay: 27 checks passed.
- Expanded extracted BOT/USB completion replay: 130 checks passed.
- The cleanup invariant failed before the correction and passed afterward.
- New actual-production-function host test: seven scenarios passed using MSVC
  14.40, C11, /W4 /WX.
- Firmware suite: 300 tests, 259 passed, 41 skipped, exit 0. Existing probes
  requiring cc explain some skips; your host may execute more.
- Manager formatting checks passed.
- No TI target build or hardware validation of this correction has occurred.

The expanded replay injects separate short completions and reproduces the
invalid-length rejection and old cleanup underflow. This injection is **not**
proof that such short transfers happened on the physical dock. Normal complete
4 KiB chunks and the final 670-byte chunk pass.

If Manager analysis tools and Windows MSVC are available, this optional command
runs the replay without device access:

```text
node analysis/scripts/review_receiver_offline.mjs <firmware-root> <ORIGINAL-approved-1.10.bin> <NEW-output-directory> <absolute-cl.exe-path> --bot
```

Run from Manager with MSVC INCLUDE/LIB/PATH configured. This tool deliberately
pins the original image hash. **Do not replace the pin with your new candidate
hash to make an old fixture accept different bytes.** It does not support a
non-MSVC compiler unchanged; the embedded regression test is portable.

## 7. Deliverables to bring back

Create a unique development-candidate directory, for example
openrdx-bot-cleanup-candidate-20260915-<short-new-container-hash>/, containing:

1. **RETURN_REPORT.md**:
    - exact source base plus patch/files included;
    - actual host/compiler/tool versions and resolved paths;
    - commands, exit codes, pass/fail/skip totals;
    - warnings, map/size observations, and limitations;
    - new container length/SHA-256, boot-region SHA-256, runtime SHA-256;
    - every candidate filename and checksum;
    - explicit statements: **not flashed**, **not a published release**,
      **original first-chunk rejection remains unresolved**;
    - explanations for any additional source changes.
2. Complete regenerated six-file bundle:
    - OpenRDX-v1-10.bin
    - OpenRDX-v1-10-FlashBurner.hex
    - OpenRDX-v1-10.json
    - OpenRDX-v1-10.sha256
    - rdx_manager_firmware_update.ps1
    - OPENRDX_USB_UPDATE.md
3. Direct TI outputs:
    - TUSB9261_RDX.out
    - TUSB9261_RDX.map
    - TUSB9261_RDX.hex
    - TUSB9261_RDX_flash.hex
4. Full test/build logs, focused source patch including new files, and a SHA-256
   inventory covering the handoff artifacts.

Keep original basenames inside the unique candidate directory so manifest
references remain valid. Do not hand-edit generated manifests/checksums. A local
ZIP for transfer is fine; uploading or publishing requires a separate request.

On failure, return the report/logs instead of labelling an incomplete or stale
bundle ready. Ask the user to bring RETURN_REPORT.md and the candidate directory
or ZIP back to the original assistant. **Stop at that handoff, without flashing.**

## 8. Optional original-machine evidence

Manager docs:

- [windows-bot-cleanup-fix-2026-09-15.md](../reports/windows-bot-cleanup-fix-2026-09-15.md)
- [windows-live-firmware-test-2026-09-15.md](../reports/windows-live-firmware-test-2026-09-15.md)
- [windows-receiver-offline-review-2026-09-15.md](../reports/windows-receiver-offline-review-2026-09-15.md)
- [windows-spti-diagnostics-2026-09-15.md](../reports/windows-spti-diagnostics-2026-09-15.md)

Windows staging root:

C:/Users/afiedler/AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Local/OpenRDXManager/Windows-20260913

Key files: read-only-boot-compare-20260915.json and
hardware-test-20260915-run1-result.json. Private SPTI/audit log locations are
listed in the live-test report. Do not overwrite
hardware-test-20260915-run1-attempt.json or rerun its single-attempt harness.

Additional host-only results:
C:/Users/afiedler/rdx-bot-review-20260915-green/, including manifest.json,
cases.txt, and python-suite-final.txt.

These files may not exist on your compiler host. The build assignment does not
require private device logs; the essential source correction and tests are
contained in this handoff.

## Appendix A — tests/test_bot_cleanup.py

Create this file if missing. Otherwise compare and preserve newer user changes.

```python
# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the actual BOT error cleanup against local endpoint accounting models."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("cc")
MSVC = shutil.which("cl")


def cleanup_probe_directory(temporary):
    """Allow Windows to release a just-executed test binary before temp cleanup."""
    for attempt in range(10):
        try:
            temporary.cleanup()
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.05)


@unittest.skipUnless(CC or MSVC, "Host logic test needs cc or configured MSVC")
class BotCleanupTests(unittest.TestCase):
    """Completion callbacks must not count an OUT transfer a second time."""

    def test_actual_cleanup_handles_active_and_completed_transfers(self):
        """Compile and execute production cleanup without USB or register access."""
        source = (ROOT / "src/rdx_mount/ums_bot.c").read_text(encoding="utf-8")
        signature = "void ums_bot_xfer_cleanup(BOOLEAN_T stall_active_endpt)"
        self.assertEqual(1, source.count(signature))
        start = source.index(signature)
        end = source.index("\n}", start) + 2
        fixture = (ROOT / "tests/fixtures/bot_cleanup_probe.c").read_text(
            encoding="utf-8"
        )
        temporary = tempfile.TemporaryDirectory(prefix="openrdx-bot-cleanup-")
        self.addCleanup(cleanup_probe_directory, temporary)
        with self.subTest(scope="RAM-only host executable"):
            tmp = temporary.name
            directory = Path(tmp)
            generated = directory / "probe.c"
            generated.write_text(
                fixture.replace("/* PRODUCTION_CLEANUP */", source[start:end]),
                encoding="utf-8",
            )
            executable = directory / ("probe.exe" if MSVC and not CC else "probe")
            if CC:
                command = [CC, "-std=c99", "-Wall", "-Wextra", "-Werror",
                           str(generated), "-o", str(executable)]
            else:
                command = [MSVC, "/nologo", "/std:c11", "/W4", "/WX",
                           str(generated), f"/Fe:{executable}",
                           f"/Fo:{directory / 'probe.obj'}"]
            built = subprocess.run(command, cwd=directory, capture_output=True,
                                   text=True, timeout=30)
            self.assertEqual(0, built.returncode, built.stdout + built.stderr)
            result = subprocess.run([str(executable)], cwd=directory,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("PASS 7 BOT cleanup scenarios", result.stdout)


if __name__ == "__main__":
    unittest.main()

```

## Appendix B — tests/fixtures/bot_cleanup_probe.c

Create this file if missing. It never opens a device. The test inserts the
actual production cleanup at the marker and compiles a temporary host executable.

```c
/*
 * SPDX-FileCopyrightText: 2026 André Fiedler
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * RAM-only regression fixture: no device or register access. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t UINT32_T;
typedef unsigned char BOOLEAN_T;
typedef struct { UINT32_T dStatus; } TRB_T;
typedef struct {
    UINT32_T dBytesRemaining, dXferLength;
    BOOLEAN_T bXferActive;
    TRB_T *pTRB;
} EP_INFO_T;
#define TRUE 1
#define FALSE 0
#define DEBUG(...) ((void)0)
#define INFO(...) ((void)0)
#define UMS_BOT_STATE_DATA_OUT 2
#define UMS_BOT_STATE_DATA_IN 1
#define BOT_BULK_OUT_ENDPT_NUM 1
#define BOT_BULK_IN_ENDPT_NUM 1
#define ENDPT_DIRECTION_OUT 0
#define ENDPT_DIRECTION_IN 0x80
#define TRB_STATUS_BUFFER_SIZE_MASK 0x00FFFFFF
static struct { EP_INFO_T ep_info_OUT[2]; } usb_dev;
static unsigned gBOT_state, out_cancels, in_cancels, out_stalls, in_stalls;
static TRB_T trb;

/** Records cancellation in RAM, including the endpoint's inactive transition. */
static void usb_hal_cancel_io_request(unsigned endpoint)
{
    if (endpoint & ENDPT_DIRECTION_IN) in_cancels++;
    else { out_cancels++; usb_dev.ep_info_OUT[1].bXferActive = FALSE; }
}
/** Records the requested stall direction without any USB call. */
static void ums_bot_stall(unsigned direction)
{ if (direction) in_stalls++; else out_stalls++; }

/* PRODUCTION_CLEANUP */

/** Initializes a single endpoint's local transfer-accounting fields. */
static void setup(unsigned state, BOOLEAN_T active, unsigned remaining,
                  unsigned residual)
{
    memset(&usb_dev, 0, sizeof(usb_dev));
    out_cancels = in_cancels = out_stalls = in_stalls = 0;
    gBOT_state = state; trb.dStatus = residual;
    usb_dev.ep_info_OUT[1].pTRB = &trb;
    usb_dev.ep_info_OUT[1].bXferActive = active;
    usb_dev.ep_info_OUT[1].dXferLength = 4096;
    usb_dev.ep_info_OUT[1].dBytesRemaining = remaining;
}

/** Exercises completed, partial, active, repeated and IN cleanup scenarios. */
int main(void)
{
    EP_INFO_T *ep = &usb_dev.ep_info_OUT[1];
    setup(2, FALSE, 0, 0); ums_bot_xfer_cleanup(TRUE);
    if (ep->dBytesRemaining || out_cancels || out_stalls || in_cancels != 1) return 1;
    setup(2, FALSE, 3584, 3584); ums_bot_xfer_cleanup(TRUE);
    if (ep->dBytesRemaining != 3584 || out_cancels || out_stalls) return 2;
    setup(2, TRUE, 4096, 1024); ums_bot_xfer_cleanup(TRUE);
    if (ep->dBytesRemaining != 1024 || out_cancels != 1 || out_stalls != 1 || ep->bXferActive) return 3;
    ums_bot_xfer_cleanup(TRUE);
    if (ep->dBytesRemaining != 1024 || out_cancels != 1 || out_stalls != 1) return 4;
    setup(2, TRUE, 4096, 0); ums_bot_xfer_cleanup(TRUE);
    if (ep->dBytesRemaining || ep->bXferActive || out_cancels || out_stalls) return 5;
    setup(2, TRUE, 4096, 1024); ums_bot_xfer_cleanup(FALSE);
    if (ep->dBytesRemaining != 1024 || out_cancels != 1 || out_stalls) return 6;
    setup(1, FALSE, 0, 0); ums_bot_xfer_cleanup(TRUE);
    if (out_cancels || out_stalls || in_cancels != 1 || in_stalls != 1) return 7;
    puts("PASS 7 BOT cleanup scenarios");
    return 0;
}
```

Return to [development documentation](README.md).
