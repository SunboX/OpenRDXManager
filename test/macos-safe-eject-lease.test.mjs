// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const hostAdapterUrl = new URL('../native/rdx-service/src/platform/macos/host.rs', import.meta.url)
const nativeAdapterUrl = new URL('../native/rdx-service/macos-native/src/lib.rs', import.meta.url)
const platformAdapterUrl = new URL('../native/rdx-service/src/platform/macos.rs', import.meta.url)
const candidateAdapterUrl = new URL('../native/rdx-service/src/platform/macos/open_candidate.rs', import.meta.url)
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
    const candidateSource = await readFile(candidateAdapterUrl, 'utf8')
    const workerSource = await readFile(workerAdapterUrl, 'utf8')
    const handoffSource = await readFile(new URL('../native/rdx-service/src/platform/macos/scsi_handoff.rs', import.meta.url), 'utf8')
    const routeSource = await readFile(new URL('../native/rdx-service/src/platform/macos/worker_route.rs', import.meta.url), 'utf8')
    const spawnSource = await readFile(new URL('../native/rdx-service/native/macos/rdx_worker_spawn.c', import.meta.url), 'utf8')
    const contextSource = await readFile(new URL('../native/rdx-service/macos-native/src/scsi_worker_context.rs', import.meta.url), 'utf8')
    const binarySource = await readFile(serviceBinaryUrl, 'utf8')
    const start = source.indexOf('struct MacOsDeviceHandle')
    const end = source.indexOf('/// Converts an exact classified packet', start)
    const implementation = source.slice(start, end)

    assert.match(implementation, /Option<rdx_macos_native::MacScsiWorkerLease>/u, 'the service handle must own only the disposable worker proxy')
    assert.doesNotMatch(implementation, /Option<rdx_macos_native::MacScsiLease>/u, 'the long-lived service must not own DeviceCapture directly')
    assert.match(source, /fn open_candidate\([\s\S]*?self\.open_registry_candidate\(candidate\)/u, 'the backend must delegate to the checked candidate acquisition module')
    assert.match(candidateSource, /invalidate_media_mapping_for_rematch\(\);[\s\S]*?failure_stage = DiscoveryFailure::WorkerAcquisition;\s*let scsi = super::scsi_handoff::release_parent_and_spawn\(Some\(authority\), \|\| \{\s*worker_route\.spawn\(&rematch_identity\)[\s\S]*?_authority: None/u, 'the candidate must transfer parent ownership into the actual release-before-factory helper')
    assert.match(handoffSource, /fn release_parent_and_spawn<A, W>\([\s\S]*?drop\(parent\);\s*spawn\(\)/u, 'the consumed helper must drop every parent client before calling the retained factory')
    assert.match(routeSource, /Self::Manager\(factory\) \| Self::Direct\(factory\) => factory\.spawn\(identity\)/u, 'capture must require an opaque native GUI or direct capability')
    assert.doesNotMatch(routeSource, /LegacyDirect|MacScsiWorkerLease::spawn|Command::new/u, 'missing or refused GUI authority must have no raw process fallback')
    const directStart = spawnSource.indexOf('static rdx_macos_status rdx_spawn_current_worker(')
    const directEnd = spawnSource.indexOf('rdx_macos_status rdx_macos_spawn_direct_worker(', directStart)
    assert.notEqual(directStart, -1)
    assert.notEqual(directEnd, -1)
    const directLauncher = spawnSource.slice(directStart, directEnd)
    assert.match(directLauncher, /_NSGetExecutablePath\(unresolved, &capacity\)[\s\S]*?realpath\(unresolved, executable\)[\s\S]*?char \*const argv\[\] = \{executable, "--openrdx-internal-macos-scsi-worker", NULL\};\s*char \*const environment\[\] = \{"LANG=C", NULL\};\s*return rdx_spawn_worker\(executable, argv, environment, 0, output\)/u, 'direct mode must resolve only its actual native current executable and fixed role/environment')
    assert.doesNotMatch(directLauncher, /launchctl|asuser/u, 'direct authority must preserve its caller session')
    assert.match(spawnSource, /rdx_macos_spawn_direct_worker\([\s\S]*?getuid\(\) != 0 \|\| geteuid\(\) != 0[\s\S]*?return rdx_spawn_current_worker\(output\)/u, 'the direct native entry must independently require actual root')
    assert.match(spawnSource, /POSIX_SPAWN_CLOEXEC_DEFAULT \| POSIX_SPAWN_SETSIGMASK \| POSIX_SPAWN_SETSIGDEF/u, 'all native launches must keep the reviewed descriptor/signal setup')
    assert.doesNotMatch(workerSource, /pub fn spawn\(|pub fn run_scsi_worker</u, 'the public raw spawn and raw INIT entry must remain unavailable')
    assert.match(contextSource, /fn child_preflight_role\([\s\S]*?ContextRequest::decode\([\s\S]*?expected\.verify\([\s\S]*?FRAME_CONTEXT_PROOF[\s\S]*?FRAME_CONTEXT_OK[\s\S]*?FRAME_INIT/u, 'every production role must prove actual context and receive ACK before INIT')
    assert.match(workerSource, /drop\(scsi\);\s*drop\(authority\);/u, 'the disposable child must preserve capture-before-parent native release ordering')
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

/**
 * Cross-checks the serial route's exact existing target, unmounted-media and USB gates around spawn.
 *
 * @returns {Promise<void>} Resolves after every consumed guard remains present and ordered.
 */
async function testSerialWorkerRetainsExactTargetAndDirectOnlyPolicy() {
    const source = await readFile(new URL('../native/rdx-service/src/serial_cli/native.rs', import.meta.url), 'utf8')
    const binary = await readFile(new URL('../native/rdx-service/src/bin/openrdx-serial.rs', import.meta.url), 'utf8')
    const worker = await readFile(workerAdapterUrl, 'utf8')
    assert.match(source, /usb\.vendor_id\(\) == 0x1a5a[\s\S]*?usb\.product_id\(\) == 5[\s\S]*?usb\.location_id\(\) != 0[\s\S]*?usb\.location_id\(\) == target\.location[\s\S]*?usb\.serial\(\) == target\.serial/u, 'only the complete explicit USB target may match')
    assert.match(source, /fn select\([\s\S]*?if selected\.is_some\(\)[\s\S]*?serial-target-ambiguous/u, 'the exact target must remain unique')
    assert.match(source, /fn acquire\([\s\S]*?select\(target\)[\s\S]*?pin_media\(\)[\s\S]*?mounted_media_count\(\) != 0[\s\S]*?serial-mounted-media-refused[\s\S]*?matches_usb\(&device\.usb_identity\([\s\S]*?drop\(device\);\s*let mut worker = rdx_macos_native::MacDirectWorkerFactory::for_current_privileged_process\(\)[\s\S]*?factory\.spawn\(&identity\)[\s\S]*?matches_usb\(&worker\.usb_identity\([\s\S]*?worker\.release_for_storage_rematch\(\)/u, 'serial must check exact unmounted parent USB evidence, drop parent before factory spawn, then verify child USB or release it')
    assert.match(binary, /args_os\(\)\.skip\(1\)\.collect::<Vec<_>>\(\) == \["--openrdx-internal-macos-scsi-worker"\][\s\S]*?run_serial_scsi_worker_stdio\(\)/u, 'serial must keep the existing sole hidden argument and its own closed role')
    assert.match(worker, /run_serial_scsi_worker_stdio\(\)[\s\S]*?context::run_stdio\(true\)/u, 'serial must use direct preflight and its own command-loop policy')
    assert.match(worker, /if serial_only[\s\S]*?usb_identity_is_valid[\s\S]*?EvidenceIncomplete[\s\S]*?authority\.acquire_scsi\(\)/u, 'the serial child must validate physical USB evidence before capture')
    assert.match(worker, /if !operation_allowed\(serial_only, request\.operation\) \{\s*return Err\(NativeError::InvalidRequest\)/u, 'serial must enforce its existing closed semantic operations before native dispatch')
}

/**
 * Cross-checks the three explicit recovery entrypoints prepare native direct authority before work.
 *
 * @returns {Promise<void>} Resolves after direct and supplied-service routes remain distinct.
 */
async function testRecoveryPreparesNativeAuthorityBeforeAttempt() {
    const source = await readFile(new URL('../native/rdx-service/src/service/recovery/native.rs', import.meta.url), 'utf8')
    const context = await readFile(new URL('../native/rdx-service/src/service/recovery/native_context.rs', import.meta.url), 'utf8')
    for (const [startText, endText] of [
        ['pub(super) fn recover(', '/// Returns only current route'],
        ['pub(super) fn recover_selected(', '/// Uses only trusted caller-held'],
        ['pub(super) fn verify_existing(', null]
    ]) {
        const start = source.indexOf(startText)
        assert.notEqual(start, -1)
        const end = endText === null ? source.length : source.indexOf(endText, start)
        assert.ok(end > start)
        const entry = source.slice(start, end)
        assert.match(entry, /acquire_owner\(\)\?;\s*with_recovery_context\(ContextAuthority::Direct, mint_direct_context, \|context\|/u, 'each direct route must obtain native authority after ownership and before entering its attempt')
        assert.doesNotMatch(entry, /privileged_direct_cli\(true\)/u, 'bare flags cannot stand in for a native factory')
    }
    assert.match(context, /fn mint_direct_context\([\s\S]*?MacDirectWorkerFactory::for_current_privileged_process\(\)[\s\S]*?privileged_direct_cli\(true\)\s*\.with_macos_direct_worker_factory\(factory\)/u, 'only the native-minted direct factory may prepare recovery context')
    assert.match(context, /ContextAuthority::Direct => mint\(\)\?,\s*ContextAuthority::Service\(context\) => context,[\s\S]*?attempt\(context\)/u, 'mint refusal must precede the attempt and service authority must pass through unchanged')
    assert.match(source, /fn recover_in_service\([\s\S]*?ContextAuthority::Service\(context\)/u, 'the authenticated service route must retain its original context')
    assert.match(source, /fn finish_release\([\s\S]*?MacOsBackend::native_with_context\(self\.context\.duplicate_for_runtime\(\)\)/u, 'finishing and fresh readback must retain the exact original recovery authority')
}

test('macOS host-fact revalidation preserves the retained protocol lease', testRetainedScsiSurvivesHostFactRevalidation)
test('macOS Safe Eject uses Disk Arbitration after releasing USB capture', testSafeEjectUsesDiskArbitration)
test('macOS Safe Eject uses a fixed Apple fallback after exact target revalidation', testSafeEjectUsesValidatedAppleFallback)
test('macOS service isolates caller-terminating USB capture in a disposable worker', testMacOsServiceUsesDisposableScsiWorker)
test('macOS Safe Eject emits fixed breadcrumbs around every native boundary', testSafeEjectPublishesClosedNativeBreadcrumbs)
test('macOS Safe Eject identifies every fresh-authority reopen boundary', testSafeEjectPublishesAuthorityReopenBreadcrumbs)
test('macOS Safe Eject confirms departure through Disk Arbitration', testSafeEjectReadbackUsesDiskArbitration)
test('macOS storage rematch enumerates both direct-access SCSI registry classes', testStorageRematchEnumeratesBothScsiRegistryClasses)

test('serial capture retains exact target and direct-only worker policy', testSerialWorkerRetainsExactTargetAndDirectOnlyPolicy)

test('direct recovery prepares native authority before mutation and retains service context', testRecoveryPreparesNativeAuthorityBeforeAttempt)
