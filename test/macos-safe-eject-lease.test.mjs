// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const hostAdapterUrl = new URL('../native/rdx-service/src/platform/macos/host.rs', import.meta.url)
const nativeAdapterUrl = new URL('../native/rdx-service/macos-native/src/lib.rs', import.meta.url)
const platformAdapterUrl = new URL('../native/rdx-service/src/platform/macos.rs', import.meta.url)
const workerAdapterUrl = new URL('../native/rdx-service/macos-native/src/scsi_worker.rs', import.meta.url)
const serviceBinaryUrl = new URL('../native/rdx-service/src/bin/openrdx-hardware.rs', import.meta.url)
const iokitAdapterUrl = new URL('../native/rdx-service/native/macos/rdx_iokit.c', import.meta.url)
const iokitDiskArbitrationUrl = new URL('../native/rdx-service/native/macos/rdx_iokit_da.c', import.meta.url)
const iokitDiscoveryUrl = new URL('../native/rdx-service/native/macos/rdx_iokit_discovery.c', import.meta.url)
const iokitRevalidateUrl = new URL('../native/rdx-service/native/macos/rdx_iokit_revalidate.c', import.meta.url)

/**
 * Proves host-fact revalidation cannot consume the retained macOS SCSI lease
 * while the operation is still validating protocol identity.
 *
 * @returns {Promise<void>} Resolves after the source invariant is validated.
 */
async function testRetainedScsiSurvivesHostFactRevalidation() {
    const source = await readFile(hostAdapterUrl, 'utf8')
    const start = source.indexOf('    fn host_volume_facts(')
    const end = source.indexOf('    /// Runs exact mount-relative native file I/O', start)
    assert.notEqual(start, -1, 'macOS host-volume adapter must remain present')
    assert.notEqual(end, -1, 'macOS host-volume adapter boundary must remain present')
    const implementation = source.slice(start, end)

    assert.match(implementation, /if self\.scsi\.is_some\(\) \{\s*if let Some\(facts\) = self\.cached_host_facts \{[\s\S]*?return Ok\(facts\);/u, 'a retained SCSI lease must reuse its exact validated host facts')
    assert.doesNotMatch(implementation, /cached_host_facts\.take\(\)/u, 'reading exact cached facts must not consume the operation lease snapshot')
}

/**
 * Proves macOS Safe Eject releases private USB capture and uses the same
 * Disk Arbitration unmount/eject route as a normal macOS removable disk.
 *
 * @returns {Promise<void>} Resolves after the source invariant is validated.
 */
async function testSafeEjectUsesDiskArbitration() {
    const source = await readFile(hostAdapterUrl, 'utf8')
    const nativeSource = await readFile(iokitDiskArbitrationUrl, 'utf8')
    const start = source.indexOf('    fn safe_eject_exact(')
    const end = source.indexOf('    /// Ejects through Disk Arbitration', start)
    assert.notEqual(start, -1, 'macOS Safe Eject adapter must remain present')
    assert.notEqual(end, -1, 'macOS Safe Eject adapter boundary must remain present')
    const implementation = source.slice(start, end)

    assert.match(implementation, /prepare_host_authority\(\)\?[\s\S]*?mapping\.unmount_for_eject\(30_000\)[\s\S]*?after_unmount\(\)[\s\S]*?mapping\.eject\(30_000\)/u, 'Safe Eject must surrender USB capture, unmount without a raw-transport claim, cross the closed checkpoint, and eject through Disk Arbitration')
    assert.match(implementation, /let eject_result = map_macos_host_outcome\(mapping\.eject\(30_000\)\)[\s\S]*?MutationCertainty::CompletionUnknown[\s\S]*?safe_eject_dispatched = true/u, 'an attempted ambiguous eject must advance to non-owning departure readback')
    assert.match(nativeSource, /clear_after_eject = eject && result->attempted != 0/u, 'every attempted eject outcome must retire its unusable retained media mapping before readback or retry')
    assert.doesNotMatch(implementation, /ScsiOperation::eject_media\(\)|map_macos_eject_completion/u, 'normal macOS Safe Eject must not use the raw START STOP UNIT fallback')
}

/**
 * Proves macOS entitlement denial and generic unmount/eject failures
 * fall back to Apple's fixed disk utility only with freshly revalidated exact
 * media authority, a bounded wait, and no command shell.
 *
 * @returns {Promise<void>} Resolves after the fallback boundary is validated.
 */
async function testSafeEjectUsesValidatedAppleFallback() {
    const source = (await Promise.all([iokitDiskArbitrationUrl, new URL('../native/rdx-service/native/macos/rdx_iokit_da_fallback.inc', import.meta.url)].map((url) => readFile(url, 'utf8')))).join('\n')

    assert.match(source, /status == RDX_MACOS_STATUS_ACCESS_DENIED[\s\S]*?kDAReturnNotPrivileged[\s\S]*?kDAReturnNotPermitted/u, 'a proven Disk Arbitration entitlement denial may cross the Apple utility fallback')
    assert.match(source, /generic_da_failure\s*=\s*status == RDX_MACOS_STATUS_NATIVE_FAILURE[\s\S]*?entitlement_denied \|\| generic_da_failure[\s\S]*?rdx_revalidate_diskutil_target\(device, eject\)[\s\S]*?rdx_run_diskutil_operation/u, 'a generic unmount or eject failure may fall back only after exact target revalidation')
    assert.match(source, /DADiskGetBSDName\(device->whole_disk\)[\s\S]*?DADiskCopyIOMedia\(device->whole_disk\)[\s\S]*?strcmp\(current_bsd_name, device->whole_bsd_name\) == 0[\s\S]*?IOObjectIsEqualTo\(disk_media, device->whole_media\)[\s\S]*?disk_media_id == device->whole_registry_entry_id[\s\S]*?rdx_fresh_whole_media_matches\(device, eject \? -1 : device->whole_raw_fd\)/u, 'fallback revalidation must bind the current BSD name to the exact retained IOMedia generation and full fresh authority')
    assert.match(source, /strncmp\(bsd_name, "disk", 4\)[\s\S]*?for \(size_t index = 4; index < length; \+\+index\)[\s\S]*?bsd_name\[index\] < '0'[\s\S]*?bsd_name\[index\] > '9'/u, 'the fallback target must be an exact whole-disk BSD name')
    assert.match(source, /char \*arguments\[\] = \{[\s\S]*?"\/usr\/sbin\/diskutil"[\s\S]*?eject \? "eject" : "unmountDisk"[\s\S]*?target[\s\S]*?NULL/u, 'the fallback must construct only Apple diskutil with fixed verbs and argv')
    assert.match(source, /posix_spawn\([\s\S]*?&child[\s\S]*?"\/usr\/sbin\/diskutil"[\s\S]*?&actions[\s\S]*?arguments[\s\S]*?environment/u, 'the fallback must execute the fixed argv directly')
    assert.match(source, /rdx_wait_for_diskutil\(child, timeout_ms\)/u, 'the Apple utility process must remain bounded by the host-operation timeout')
    assert.match(source, /macos-da-direct-access-denied/u, 'the direct Disk Arbitration denial must remain visible as a closed diagnostic')
    assert.match(source, /!eject[\s\S]*?kDAReturnNotMounted[\s\S]*?macos-da-direct-already-unmounted[\s\S]*?kDAReturnSuccess/u, 'an already-unmounted exact whole disk must satisfy only the unmount postcondition')
    assert.match(source, /macos-diskutil-unmount-enter[\s\S]*?macos-diskutil-unmount-succeeded[\s\S]*?macos-diskutil-unmount-exit-nonzero/u, 'the fallback must distinguish dispatch, success, and a nonzero Apple utility result')
    assert.doesNotMatch(source, /\b(?:system|popen)\s*\(/u, 'the entitlement fallback must never invoke a command shell')
}

/**
 * Proves the long-lived service never directly owns Apple's caller-terminating
 * DeviceCapture lease.
 *
 * @returns {Promise<void>} Resolves after the process boundary is validated.
 */
async function testMacOsServiceUsesDisposableScsiWorker() {
    const source = await readFile(platformAdapterUrl, 'utf8')
    const workerSource = await readFile(workerAdapterUrl, 'utf8')
    const binarySource = await readFile(serviceBinaryUrl, 'utf8')
    const start = source.indexOf('struct MacOsDeviceHandle')
    const end = source.indexOf('/// Converts an exact classified packet', start)
    const implementation = source.slice(start, end)

    assert.match(implementation, /Option<rdx_macos_native::MacScsiWorkerLease>/u, 'the service handle must own only the disposable worker proxy')
    assert.doesNotMatch(implementation, /Option<rdx_macos_native::MacScsiLease>/u, 'the long-lived service must not own DeviceCapture directly')
    assert.match(source, /invalidate_media_mapping_for_rematch\(\);\s*drop\(authority\);\s*let scsi = rdx_macos_native::MacScsiWorkerLease::spawn[\s\S]*?_authority: None/u, 'the parent must release every IOKit device client before the worker captures USB')
    assert.match(workerSource, /Command::new\(executable\)[\s\S]*?\.arg\("--openrdx-internal-macos-scsi-worker"\)/u, 'the proxy must spawn only the current executable in its fixed hidden mode')
    assert.match(binarySource, /--openrdx-internal-macos-scsi-worker[\s\S]*?arguments\.next\(\)\.is_none\(\)[\s\S]*?current_process_is_authorized\(\)[\s\S]*?run_scsi_worker/u, 'the hidden mode must reject extra arguments and require inherited privileged authority')
}

/**
 * Proves the two Disk Arbitration mutations emit fixed, non-sensitive
 * before/after breadcrumbs for live outcome localization.
 *
 * @returns {Promise<void>} Resolves after the source diagnostic contract is validated.
 */
async function testSafeEjectPublishesClosedNativeBreadcrumbs() {
    const source = await readFile(hostAdapterUrl, 'utf8')
    const start = source.indexOf('    fn safe_eject_exact(')
    const end = source.indexOf('    /// Ejects through Disk Arbitration', start)
    const implementation = source.slice(start, end)
    const breadcrumbs = ['eject-da-unmount-enter', 'eject-da-unmount-return', 'eject-stage-advance-enter', 'eject-stage-advance-return', 'eject-da-eject-enter', 'eject-da-eject-return']

    let previous = -1
    for (const breadcrumb of breadcrumbs) {
        const position = implementation.indexOf(`openrdx-hardware: trace ${breadcrumb}`)
        assert.ok(position > previous, `${breadcrumb} must follow the prior Safe Eject boundary`)
        previous = position
    }
}

/**
 * Proves a failed fresh-authority handoff identifies its exact bounded stage.
 *
 * @returns {Promise<void>} Resolves after the diagnostic sequence is validated.
 */
async function testSafeEjectPublishesAuthorityReopenBreadcrumbs() {
    const source = await readFile(nativeAdapterUrl, 'utf8')
    const start = source.indexOf('    pub fn open_after_storage_rematch(')
    const end = source.indexOf('    /// Unmounts the already pinned', start)
    const implementation = source.slice(start, end)
    const breadcrumbs = ['eject-authority-enumerate-enter', 'eject-authority-enumerate-return', 'eject-authority-select-return', 'eject-authority-open-enter', 'eject-authority-open-return']

    let previous = -1
    for (const breadcrumb of breadcrumbs) {
        const position = implementation.indexOf(`openrdx-hardware: trace ${breadcrumb}`)
        assert.ok(position > previous, `${breadcrumb} must follow the prior authority-reopen boundary`)
        previous = position
    }
}

/**
 * Proves departure readback requires a successfully dispatched host eject and
 * confirms that the exact Disk Arbitration media remains absent across two
 * consecutive non-owning observations.
 *
 * @returns {Promise<void>} Resolves after the source invariant is validated.
 */
async function testSafeEjectReadbackUsesDiskArbitration() {
    const source = await readFile(hostAdapterUrl, 'utf8')
    const start = source.indexOf('    fn verify_eject_departure(')
    const end = source.indexOf('    fn verify_format_rediscovery(', start)
    assert.notEqual(start, -1, 'macOS eject readback adapter must remain present')
    assert.notEqual(end, -1, 'macOS eject readback boundary must remain present')
    const implementation = source.slice(start, end)

    assert.match(implementation, /if !self\.safe_eject_dispatched/u, 'readback must be closed before a successful physical-eject dispatch')
    assert.match(implementation, /authority_mut\(\)\?[\s\S]*?\.media_present_without_mapping\(\)/u, 'readback must query exact media presence without acquiring raw-disk authority')
    assert.match(implementation, /SafeEjectDepartureConfirmation::default\(\)/u, 'readback must retain bounded confirmation state across fresh observations')
    assert.match(implementation, /departure_confirmation\.observe\(observation\)/u, 'readback must require stable classified departure evidence before succeeding')
    assert.match(implementation, /SafeEjectDepartureReadbackState::Departed[\s\S]*?return Ok\(\(\)\)/u, 'readback must succeed only from classified exact departure evidence')
    assert.doesNotMatch(implementation, /pin_media\(\)|invalidate_media_mapping_for_rematch\(\)/u, 'readback must neither retain nor repeatedly tear down a raw-disk mapping')
    assert.doesNotMatch(implementation, /ScsiOperation::inquiry_media_identification\(\)|observe_macos_media_departure/u, 'readback must not reacquire raw USB transport after Disk Arbitration eject')
}

/**
 * Proves storage rematch can recover the same RDX identity from either macOS
 * SCSI registry class without publishing the same physical device twice.
 *
 * @returns {Promise<void>} Resolves after the recovery contract is validated.
 */
async function testStorageRematchEnumeratesBothScsiRegistryClasses() {
    const source = await readFile(iokitAdapterUrl, 'utf8')
    const discoverySource = await readFile(iokitDiscoveryUrl, 'utf8')
    const revalidateSource = await readFile(iokitRevalidateUrl, 'utf8')

    assert.match(source, /rdx_is_scsi_candidate_service[\s\S]*?IOSCSIPeripheralDeviceNub[\s\S]*?IOSCSILogicalUnitNub/u, 'candidate validation must accept both macOS direct-access SCSI registry classes')
    assert.match(discoverySource, /rdx_append_matching_candidates[\s\S]*?"IOSCSIPeripheralDeviceNub"[\s\S]*?rdx_append_matching_candidates[\s\S]*?"IOSCSILogicalUnitNub"/u, 'enumeration must query both storage-driver generations')
    assert.match(discoverySource, /rdx_stable_candidate_identity_matches/u, 'the two class results must be deduplicated by complete stable identity')
    assert.match(revalidateSource, /rdx_macos_enumerate[\s\S]*?rdx_stable_candidate_identity_matches/u, 'rebind must use the same two-class, stable-identity enumeration')
}

test('macOS host-fact revalidation preserves the retained protocol lease', testRetainedScsiSurvivesHostFactRevalidation)
test('macOS Safe Eject uses Disk Arbitration after releasing USB capture', testSafeEjectUsesDiskArbitration)
test('macOS Safe Eject uses a fixed Apple fallback after exact target revalidation', testSafeEjectUsesValidatedAppleFallback)
test('macOS service isolates caller-terminating USB capture in a disposable worker', testMacOsServiceUsesDisposableScsiWorker)
test('macOS Safe Eject emits fixed breadcrumbs around every native boundary', testSafeEjectPublishesClosedNativeBreadcrumbs)
test('macOS Safe Eject identifies every fresh-authority reopen boundary', testSafeEjectPublishesAuthorityReopenBreadcrumbs)
test('macOS Safe Eject confirms departure through Disk Arbitration', testSafeEjectReadbackUsesDiskArbitration)
test('macOS storage rematch enumerates both direct-access SCSI registry classes', testStorageRematchEnumeratesBothScsiRegistryClasses)
