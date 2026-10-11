<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Firmware update implementation

These notes record firmware readback and reconnect regressions and their verification. Use the [firmware update guide](../firmware-updates.md) and [migration guide](../migration.md) for operator steps. Release validation and historical activation details are retained in the [firmware protocol reference](../protocols/firmware-update.md#openrdx-release-validation-checkpoints).

## Reconnect reporting regression (2026-09-10)

A physical v1.07 attempt reached mode-5 and the dock subsequently reported `0107` through macOS IORegistry (`IOSCSIPeripheralDeviceNub` / `Product Revision Level`). Its USB `bcdDevice` was also `0x0107`. The desktop nevertheless reported `service-exited` during reconnect. This confirms installation separately from the failed application operation.

The production backend could stop on a stale native reopen recipe after a successful discovery scan: releasing the scan's USB capture can cause another storage-driver rematch. It now retries a fresh scan/reopen or failed identity probe within the activation deadline, preserving activation evidence and never repeating firmware writes merely because reopen failed.

The original error was also obscured by a lifecycle-contract violation. A backend failure ended at `device-reconnecting` although the service required final verification after firmware writing. The worker now performs the final verification step with either fresh same-handle facts or an explicit unavailable-binding result, retaining the reconnect failure as the primary cause. Transfer failures also complete the recovery checkpoints and attempt read-only verification while retaining the original failure and uncertain cleanup status. An invalidated transfer lease never dispatches a finalizer. Matching revision alone cannot turn a failed transfer into success. The worker does not invent successful readback or relax the lifecycle validator. Regression tests feed all production backend events through the actual service runtime, including timeout, wrong readback, post-scan handle invalidation, transient readback-probe failure, exhausted/nonretryable transfer failure, and same-release lost-finalizer-reply cases.

The reconnect correction was tested with simulated transports. The observed physical v1.07 installation was the user's preceding attempt; no additional physical flash was performed to test this correction.

### Same-version reconnect follow-up

The later attempt `op:2ac0f8dc-68fb-4d39-af6e-7ffd8ac47510` reached reconnect at `2026-09-10T16:39:08.198Z` and failed readback at `16:39:23.244Z` with the original `stale-device-revision` error. The service remained alive, confirming the lifecycle-reporting correction, but the 15-second activation check still rejected a same-version reinstall.

The earlier simulated platform exposed every reset as an empty scan. Real macOS discovery deliberately waits up to three seconds for storage rematch (`platform/macos/refresh.rs::enumerate_after_storage_rematch`) and can reuse cached protocol evidence for the same serial and revision (`MacOsBackend::refresh_candidate_host_facts`). It can therefore hide the brief disappearance entirely. Requiring a visible gap after an acknowledged commit was incorrect. The same-version path now uses the commit/readback contract above. Regression coverage includes cached discovery with no observable gap, checks for fresh INQUIRY after mode-5 before success, and rejects unchanged firmware after two uncertain finalizer replies. It never treats cached inventory alone as successful verification.

### Protocol cache during firmware readback

The attempt at `2026-09-10T18:26:23Z` reached reconnect and failed after 15 seconds. Its logs do not identify which binding comparison failed, and the operating system's subsequent `0107` revision cannot distinguish two builds of v1.07.

Production-backend tests reproduced the same timeout when discovery reused pre-update protocol evidence: both a revision change and a same-version configuration change could leave fresh handle validation comparing against stale values forever. Firmware rediscovery now calls `discover_firmware_device_report` on every attempt. It refreshes INQUIRY, capabilities, and configuration for the exact updated dock, while preserving non-disruptive host refresh for other docks. Normal registry identity checks, empty-bay validation, commit evidence, retry limits, and expected-revision checks remain required.

The correction is verified with simulated transports, including an independent two-dock cache test. No physical firmware transfer was performed to verify this change.

### Service restart during concurrent status reads

The attempts at `2026-09-10T18:47:37Z` and `18:47:59Z` reached reconnect before the native service exited with a nonzero status. Electron remained running; restarting the service reset its displayed state and looked like a window reload.

The fresh firmware scans above were incorrectly replacing the backend's public device cache during the operation, without publishing a corresponding inventory event. An ordinary device-list request could then encounter changed snapshots under the old list revision. The service correctly rejected that inconsistent backend result, but consequently exited. A production-backend regression test reproduces `ServiceProtocolError::BackendContract` by interleaving status reads with a same-version update whose configuration changes.

Firmware reconnect scans now update only the worker's private registry. After fresh readback verifies the exact dock and expected firmware, the service loop commits the resulting public inventory and emits its device-list event immediately before the successful operation result. Concurrent readers retain the last published inventory until that boundary. The consistency check remains enforced, and failed verification cannot publish success.

The regression test uses the actual hardware worker, service runtime, framing, and a simulated platform. It checks public inventory throughout reconnect and the final device-event/operation-event order. This correction has not been verified by another physical firmware transfer.

Verification of the service restart correction:

- The new concurrent-reader test reproduced `BackendContract` before the correction and passes afterward.
- `npm run native:check` and `npm run native:check:no-default` pass. The native suite passes 425 tests when excluding the previously observed `scan_without_a_platform_adapter_is_a_safe_empty_success` stderr assertion; an unfiltered run still fails that assertion.
- A real Electron replay sends the changed device inventory before firmware success. It retains the same document and renderer process, displays the green confirmation with the fixture drive serial, and hides the banner after five foreground seconds while retaining the completed result. The replay uses simulated events and does not perform a firmware write.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke` rebuilds the development runtime and passes with the renderer mounted. Its unprivileged test process reports hardware service unavailable, so this is launch proof only.
- The JavaScript suite still encounters the existing consecutive screenshot-set hash stability assertion. A command-tree timeout assertion also failed under concurrent load and passed on recheck. `npm run format:check` and `git diff --check` pass.

### Retaining the reconnect probe through verification

The subsequent attempt `op:48d2ed56-ccd1-4422-8d8b-9f572d7982a6` used the rebuilt helper started at `2026-09-10T19:12:06Z`. It reached reconnect at `19:12:24.949Z` and failed after 15 seconds with `stale-device-revision`; the helper remained alive. Two later read-only status refreshes on the same physical dock completed successfully and the UI reported 1.07. That does not distinguish the installed contents of two different v1.07 builds.

Fresh discovery was still releasing its probe before registry resolution opened the device again. The macOS bridge explicitly resets/rematches storage when releasing its USB capture (`native/macos/rdx_usb_host.m`, `rdx_macos_usb_bot_release` and `RDXUSBHostLease::destroyWithDiagnostics`). Repeating a fresh scan can therefore repeatedly invalidate the recipe needed by the immediately following reopen; retrying that sequence does not guarantee progress.

Firmware discovery now retains the exact selected probe lease privately while committing its fresh registry evidence. Registry resolution and firmware readback reuse that live lease and repeat the normal identity, capability, media, and revision checks. The lease is released after the verification decision. Intermediate polls release their previous probe before opening another one; no handle or locator enters the public inventory. Successful inventory publication still occurs in the service loop before the terminal result.

The production-backend regression reproduces the 15-second failure when every post-reset probe/reopen cycle invalidates its recipe. Coverage includes both observed departure and a hidden same-version restart, requires success without attempting that second open, and retains the exact firmware-write count. The correction is tested with simulated transports; the physical status reads above did not exercise the corrected post-transfer path.

The 18-case production firmware matrix and the concurrent inventory-reader regression pass as part of the native suite (425 passed, the previously known CLI stderr assertion excluded). Formatting, compilation, and Clippy pass with and without default features. The rebuilt Electron development runtime passes the launch smoke check; no post-change physical firmware transfer is claimed.

### Restoring vendor 2.83 from an OpenRDX receiver (2026-09-11)

The user's restoration with the original `RDX2E__STD__F-0283.bin`, operation `op:ab2f0bbe-dc44-42e4-8b8d-d0c40a3bed7a`, reached firmware writing at `04:28:16.903Z`, reconnect at `04:28:17.964Z`, and failed version readback at `04:28:18.197Z`. Subsequent read-only IORegistry inspection of the same dock (USB serial `007360242889`) reported SCSI revision `0283` and USB `bcdDevice = 643` (`0x0283`). This is evidence that the user's restoration activated vendor 2.83 despite the failed application result. Electron, its renderer, and the hardware helper still had their original `04:15` process start times; no matching macOS crash report was found. The observed window had lost its selected-device view and showed discovery while the dock remained listed in the rail.

The activation wait incorrectly depended on the selected image's `OpenRdxIntegrityVerified` format. An original vendor image therefore took the immediate vendor readback path even while an OpenRDX receiver still governed the delayed reset. The receiver source `rdx_manager_protocol.c::rdx_manager_handle_write_buffer` commits and schedules that same reset for both the pinned compatibility image and OpenRDX images. Receiver behavior must be selected from the freshly read installed revision, independently of the image being installed.

The known receiver-revision predicate is now shared by image admission and activation reconciliation. Restoring vendor firmware from `0001`, `0106`, or `0107` waits for activation and then verifies the exact retained dock identity, empty bay, and expected vendor revision. RSA validation for the original image, the receiver allowlist, and firmware retry limits are unchanged. The real-worker/service regression fails before this change with `host-operation-failed` at `firmware-readback` and passes afterward. It covers all three receiver revisions, a lost finalizer reply, wrong-version rejection, stable public inventory during reconnect, ordered terminal publication, and exactly one complete image transfer.

The correction is exercised with simulated transports. The IORegistry evidence above verifies the user's preceding installation; no additional hardware flash was performed to test the correction.
