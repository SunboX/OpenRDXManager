<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Command line

## Command-Line Interface

### Windows development resize performance

On the tested Parallels Windows guest, GPU compositing was enabled but page
rasterization used the CPU. An optional development launch setting enables GPU
rasterization without changing any CSS, gradients, scanlines, or border geometry:

```powershell
$env:OPENRDX_WINDOWS_GPU_RASTERIZATION = '1'
npm start
```

This override is opt-in because Chromium's `enable-gpu-rasterization` switch
overrides rasterization eligibility, including its rasterization blocklist.
It is not a global driver-blocklist bypass, but other GPUs remain unqualified.
See [Chromium's rasterization selection](https://chromium.googlesource.com/chromium/src/+/main/gpu/config/gpu_util.cc).
Remove the environment variable to return to the normal defaults. Explicit
`--disable-gpu`, `--disable-gpu-compositing`, or `--disable-gpu-rasterization`
arguments take precedence; macOS/Linux launches are unchanged.

### Native CLI

Run the development CLI through the checked-in Cargo package:

```sh
npm run native:cli -- --help
npm run native:cli -- --version
npm run native:cli -- --scan
npm run native:cli -- --eject rdx:opaque-device-id
npm run native:cli -- --eject rdx:opaque-device-id --force
```

`--help`, `--version`, and usage errors are resolved before the native backend
is created. Operational success and failure output uses one compact JSON object
per line; help and version use stable plain text. Output has no ANSI-dependent
formatting. The version comes from `native/rdx-service/Cargo.toml` package
metadata.

Every record is explicitly flushed. Exit `3` is guaranteed when Rust's
`Write` or `flush` API reports an output failure, including a broken pipe. On
Unix, Rust's standard stdout/stderr implementation deliberately treats `EBADF`
from a closed or read-only inherited standard descriptor as discarded output
and returns success. Without unsafe or non-portable descriptor probes,
`rdxctl` cannot distinguish that case, so it preserves the command's ordinary
exit status. Exit `3` is therefore not promised for every invalid inherited
descriptor.

An eject target is a service-issued opaque `rdx:` identifier containing only
ASCII letters, digits, colons, and hyphens, with a total length of 5 through
128 bytes. It is not an operating-system device path. Diagnostics never repeat
the supplied target. The CLI accepts no raw CDB, raw payload, filesystem path,
command, password, secret, or arbitrary parameter.

The stable process exit codes are:

| Code | Meaning                                                       |
| ---: | ------------------------------------------------------------- |
|    0 | Informational command or requested operation succeeded        |
|    2 | Invalid, duplicate, combined, unknown, or ambiguous CLI usage |
|    3 | Local service, host transport, or output-channel failure      |
|    4 | Definitive terminal SCSI rejection                            |
|    5 | Prerequisite or capability rejection                          |
|    6 | Partial operation or ambiguous completion                     |

`--force` is valid only with `--eject`. It changes host eject policy only and
always writes a cached-data-risk warning before backend work, including when a
later prerequisite or device action fails. It does not bypass native identity,
capability, media-state, transport, or device safety gates.

CLI scan and eject use the same `ServiceRuntime`, inventory validation,
revision/capability/media admission, lifecycle graph, and high-level operation
types as the framed Electron service. Eject takes an exclusive ownership
capability, repeats exact-session preflight, and uses a typed `Safe` or `Forced`
host-cache policy. A success terminal is accepted only with the non-forgeable
safe-Rust departure capability returned after successful dispatch and fresh
exact-target readback. Typed preflight, dispatch-certainty, terminal, crash,
and readback evidence determines exits `3` through `6`; an unknown reason never
defaults to exit `4`. After eject dispatch, every failure to obtain
unambiguous exact-target readback is exit `6`, even when the same typed host
error would have been exit `3` or `5` before dispatch.

Backends cannot publish caller-authored terminal JSON. Started and progress
events require native owner/progress capabilities; success and safe
cancellation are derived from a completed native operation report, failed
events are canonically derived from the typed primary, cleanup, and recovered
attempt evidence, and eject success additionally requires verified departure.
The framed Electron path and direct CLI therefore serialize or classify the
same native terminal truth.

Cancellation acknowledgement carries a private monotonic publication cutover.
Events already admitted to the native FIFO at or before that cutover retain
their pre-request cancellation state when the bounded backlog drains; every
later publication must carry `requested`. Electron main requires both the
cutover and each operation event's publication sequence, accepts only the exact
next generation sequence for the reserved operation's immutable kind, device,
revision, and generation tuple, and rejects replay, gaps, wrap attempts,
foreign ownership, and invalid lifecycle order before any observer. Each
reservation records its sequence base and counts exactly 130 total lifecycle
publications. A cancellation cutover cannot precede the highest sequence
Electron already consumed or exceed that reservation base plus 130. The
sequence resets only for a new service generation; neither proof value is
exposed to the renderer. Any downstream lifecycle rejection faults that exact
generation and discards its queued frame suffix.

Each accepted operation has a 30-minute absolute service deadline and a
130-event total lifecycle budget (start, at most 128 native progress records,
and terminal). The service handles at most eight backend events before checking
the reserved crash path and client control input. Reaching either lifetime
bound ends the generation without inventing a terminal, so ownership remains
ambiguous. The direct CLI uses one absolute command deadline rather than
renewing a timeout after each progress event. Electron activity logging admits
at most 256 pending records and 2 MiB by default. One record plus one maximum
record-size byte partition are reserved from progress for terminal, error,
service, and audit records. Only contiguous same-operation progress at the
queue tail coalesces, so it cannot move across intervening audit data. Each
persistence attempt has a five-second bound; a timeout fail-closes the logger,
rejects queued work without starting another filesystem operation, and
escalates the service to terminal `event-log-unavailable`. Shutdown returns the
same typed sanitized close result after accepted work drains or the bound wins.
Losing a priority record also fail-closes admission and latches the same fatal
runtime health state, even during transport recovery or shutdown; it cancels
pending restart and cannot be cleared by relaunching that runtime.
Service `ready` and operation terminal truth cross their public listener and
IPC boundaries only after the corresponding critical record has both entered
the bounded logger and persisted successfully. Terminal ownership remains held
across that barrier. Admission failure, persistence rejection, or timeout
suppresses the public state, discards remaining coalesced service frames,
reconciles the exact generation, and publishes one fatal
`event-log-unavailable` service result without recursively logging it.

Safe eject cancellation is accepted only through `host-unmounting`. A request
accepted before unmount prevents unmount, eject, and readback; a request that
wins while unmount is in progress prevents eject dispatch and therefore needs
no departure readback. Immediately before host eject, an atomic mutation
barrier closes cancellation. Once `host-ejecting` begins, departure readback is
mandatory and a late request is rejected as closed. Forced eject is
non-cancellable from its first `host-ejecting` stage. These stages and terminals
match the Electron operation lifecycle policy.

Phase 3 provides platform-owned Windows, Linux, and macOS discovery, transport,
host-operation, and privileged-endpoint implementations. Development builds on
macOS and Linux authorize and launch the repository-built debug helper directly;
they never connect to an installed platform service. The helper still requires
exact device/media authority and every operation-policy confirmation and
lifecycle gate.

Native adapters and fixture/cross-target coverage are not physical proof. A
no-device scan exits successfully with an empty device array and
`hardwareVerified: false`. On this Mac, the development helper has completed an
elevated application scan and validated the attached TANDBERG RDX dock without
an installed service. Windows and Linux still require their own native-host and
attached-device acceptance. Packaging, signing, publishing, and broader physical
RDX operation validation remain separate work.

## Serial Utility

The macOS `openrdx-serial` command can inspect a dock’s manufacturing serial and prepare a private backup before changing it. Applying a prepared change requires firmware support and an empty dock. See [the serial utility guide](../../docs/serial-utility.md) for usage and recovery limits.

Return to [development documentation](README.md).
