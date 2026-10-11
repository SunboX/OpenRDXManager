// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { isNativeDiagnosticCode } from '../src/main/device-service-transport.mjs'

/** Reads production routing without opening a device or performing a mutation. */
async function source(path) {
    return readFile(new URL(`../native/rdx-service/windows-native/src/${path}`, import.meta.url), 'utf8')
}

/** Both normal branches retain their volume authority; force remains a separate route. */
async function testSafeLeaseRouting() {
    const host = await source('host.rs')
    const noMount = host.slice(host.indexOf('pub fn eject_if_unmounted('), host.indexOf('impl std::fmt::Debug for VolumeLeaseSet'))
    assert.ok(noMount.indexOf('self.mount_path_count != 0') < noMount.indexOf('.prepared_safe_eject('))
    assert.ok(noMount.indexOf('revalidate_volume_leases(&self.leases)') < noMount.indexOf('.prepared_safe_eject('))
    assert.match(noMount, /prepared_safe_eject\(&self\.leases\)/u)
    const dismounted = host.slice(host.indexOf("impl ValidatedVolumeMutationLease<'_>"))
    assert.match(dismounted, /prepared_safe_eject\(&self\.volumes\.leases\)/u)
    assert.equal(host.match(/\.prepared_safe_eject\(/gu)?.length, 2)
    const force = host.slice(host.indexOf('pub fn force_eject('), host.indexOf('pub fn media_identity_material('))
    assert.match(force, /self\.inner\.eject_media\(\)/u)
    assert.doesNotMatch(force, /prepared_safe_eject|allow_windows_removal/u)
}

/** The unlock sequence stays private, exact-handle, no-data, and before physical eject. */
async function testClosedPreparationBoundary() {
    const native = await source('native/safe_eject.rs')
    const policy = await source('safe_eject.rs')
    const publicApi = await source('lib.rs')
    assert.match(native, /PREVENT_MEDIA_REMOVAL\s*\{\s*PreventMediaRemoval: false/u)
    assert.match(native, /kernel_handle\(&device\.handle\),\s*IOCTL_STORAGE_MEDIA_REMOVAL/u)
    assert.match(native, /execute_buffered\(\s*kernel_handle\(&self\.device\.handle\),\s*allow_device_removal_request\(\)/u)
    assert.match(native, /validate_allow_device_removal\(completion\)/u)
    const sequence = policy.slice(policy.indexOf('pub(super) fn run_prepared_safe_eject('), policy.indexOf('/// Builds only'))
    assert.ok(sequence.indexOf('SafeEjectStep::AllowWindowsRemoval') < sequence.indexOf('SafeEjectStep::AllowDeviceRemoval'))
    assert.ok(sequence.indexOf('SafeEjectStep::AllowDeviceRemoval') < sequence.indexOf('SafeEjectStep::Eject'))
    assert.doesNotMatch(publicApi, /pub fn allow_device_removal|AllowDeviceRemoval|AllowWindowsRemoval/u)
}

test('Windows safe eject prepares removal only under retained normal-eject leases', testSafeLeaseRouting)
test('Windows safe eject keeps both allow-removal steps private and ordered', testClosedPreparationBoundary)

/** Causal diagnostics remain a closed vocabulary, never a raw stderr passthrough. */
async function testBoundedStepDiagnostics() {
    const native = await source('native/safe_eject.rs')
    const codes = ['windows-safe-eject-binding-failed', 'windows-safe-eject-allow-os-succeeded', 'windows-safe-eject-allow-os-failed', 'windows-safe-eject-allow-device-succeeded', 'windows-safe-eject-allow-device-failed', 'windows-safe-eject-ioctl-succeeded', 'windows-safe-eject-ioctl-failed']
    for (const code of codes) {
        assert.ok(native.includes(code))
        assert.equal(isNativeDiagnosticCode(code), true)
        assert.equal(isNativeDiagnosticCode(`${code} private device data`), false)
    }
    assert.equal(isNativeDiagnosticCode('windows-safe-eject-arbitrary'), false)
}

test('Windows safe eject exposes only fixed step outcomes for failure diagnosis', testBoundedStepDiagnostics)
