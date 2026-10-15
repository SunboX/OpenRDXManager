// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { getWindowsClientAddonBuildPaths } from '../scripts/build-windows-client-addon.mjs'
import { createWindowsNativeEndpointConnector } from '../src/main/windows-native-endpoint.mjs'

const projectRoot = process.cwd()

test('Windows native client source excludes pipe-instance creation and verifies exact service authority', async () => {
    const source = await readFile(join(projectRoot, 'native/windows-client-addon/openrdx_windows_client.cc'), 'utf8')

    assert.match(source, /kClientAccess = FILE_READ_DATA \| FILE_WRITE_DATA \|/u)
    assert.doesNotMatch(source, /kClientAccess[^;]*(?:GENERIC_WRITE|FILE_CREATE_PIPE_INSTANCE)/su)
    assert.match(source, /GetNamedPipeServerProcessId/u)
    assert.match(source, /SERVICE_RUNNING/u)
    assert.match(source, /SERVICE_WIN32_OWN_PROCESS/u)
    assert.match(source, /WinLocalServiceSid/u)
    assert.match(source, /SameFileIdentity/u)
    assert.match(source, /first_status\.dwProcessId == second_status\.dwProcessId/u)
    assert.match(source, /std::lock_guard<std::mutex> lock\(connection->write_mutex\)/u)
    assert.doesNotMatch(source, /ShellExecute|CreateProcess|system\s*\(/u)
})

test('Windows overlapped operations retain storage through exact cancellation completion', async () => {
    const source = await readFile(join(projectRoot, 'native/windows-client-addon/openrdx_windows_client.cc'), 'utf8')

    assert.match(source, /struct PendingIo[\s\S]*OVERLAPPED overlapped[\s\S]*std::vector<std::uint8_t> storage/u)
    assert.match(source, /CancelAndDrainPendingIo\([\s\S]*CancelIoEx\(operation->pipe\.value, &operation->overlapped\)[\s\S]*WaitForSingleObject\(operation->event\.value, kCancelDrainTimeoutMs\)[\s\S]*ObservePendingIoTerminal/u)
    assert.match(source, /ObservePendingIoTerminal\([\s\S]*GetOverlappedResult\([\s\S]*GetLastError\(\) != ERROR_IO_INCOMPLETE/u)
    assert.match(source, /PreservePendingIoForProcessLifetime/u)
    assert.doesNotMatch(source, /OVERLAPPED operation\{\}/u)
    assert.doesNotMatch(source, /CancelIoEx\([^,]+, nullptr\)/u)
    assert.doesNotMatch(source, /WaitForSingleObject\([^,]+, INFINITE\)/u)
})

test('Windows pending I/O reserves one fixed aggregate budget before kernel admission', async () => {
    const source = await readFile(join(projectRoot, 'native/windows-client-addon/openrdx_windows_client.cc'), 'utf8')

    assert.match(source, /kMaxPendingIoCount = 8/u)
    assert.match(source, /kMaxPendingIoBytes = 9 \* 1024 \* 1024/u)
    assert.match(source, /TryReservePendingIoBudget\([\s\S]*count >= kMaxPendingIoCount[\s\S]*bytes > kMaxPendingIoBytes - reservation_bytes/u)
    assert.match(source, /class IoReservation[\s\S]*~IoReservation\(\)[\s\S]*ReleasePendingIoBudget/u)
    assert.match(source, /CreatePendingIo\([\s\S]*TryReservePendingIoBudget[\s\S]*make_unique<PendingIo>/u)
    assert.match(source, /Worker\([\s\S]*CreatePendingIo\(65'540[\s\S]*ReadFile/u)
    assert.match(source, /napi_value Write\([\s\S]*CreatePendingIo\(length[\s\S]*WriteFile/u)
    assert.match(source, /PreservePendingIoForProcessLifetime\(std::move\(\*owned_operation\)\)/u)
    assert.doesNotMatch(source, /\.detach\(\)|std::thread\(ReapPendingIo/u)
})

test('Windows connector uses bounded synchronous name wait before verified overlapped open', async () => {
    const source = await readFile(join(projectRoot, 'native/windows-client-addon/openrdx_windows_client.cc'), 'utf8')
    const openVerifiedPipe = source.slice(source.indexOf('HANDLE OpenVerifiedPipe'), source.indexOf('void Worker'))

    assert.match(openVerifiedPipe, /RemainingMilliseconds\(activation_deadline, kServicePollMs\)[\s\S]*WaitNamedPipeW\(kPipeName, wait\)[\s\S]*CreateFileW\([\s\S]*FILE_FLAG_OVERLAPPED/u)
    assert.doesNotMatch(openVerifiedPipe, /\bOVERLAPPED\s+[a-z]|ConnectNamedPipe/u)
})

test('Windows native adapter forwards error then exactly one observed close after destroy', () => {
    let callback
    let destroyCalls = 0
    const connector = createWindowsNativeEndpointConnector({
        addonPath: join(projectRoot, 'fixture.node'),
        loadAddon: () => ({
            /** @param {string} _expected - Fixed executable. @param {Function} handler - Native event callback. @returns {object} Controlled connection. */
            connect(_expected, handler) {
                callback = handler
                return {
                    /** @returns {boolean} Accepts no fixture writes. */
                    write() {
                        return false
                    },
                    /** @returns {void} Records one bounded native destroy request. */
                    destroy() {
                        destroyCalls += 1
                    },
                    /** @returns {void} Records no graceful fixture behavior. */
                    end() {}
                }
            }
        })
    })
    const socket = connector({ path: String.raw`\\.\pipe\OpenRDXHardwareService`, expectedExecutable: '/work/OpenRDXManager/openrdx-hardware.exe' })
    const events = []
    socket.on('error', (error) => events.push(`error:${error.reason}`))
    socket.on('close', () => events.push('close'))

    callback({ type: 'error', reason: 'service-not-installed' })
    socket.destroy()
    callback({ type: 'close' })
    callback({ type: 'close' })
    socket.destroy()

    assert.deepEqual(events, ['error:service-not-installed', 'close'])
    assert.equal(destroyCalls, 1)
})

test('Windows native worker closes after every pre-connect failure without joining in destroy', async () => {
    const source = await readFile(join(projectRoot, 'native/windows-client-addon/openrdx_windows_client.cc'), 'utf8')
    const worker = source.slice(source.indexOf('void Worker'), source.indexOf('Connection* Unwrap'))
    const destroy = source.slice(source.indexOf('napi_value Destroy'), source.indexOf('napi_value Write'))

    assert.match(worker, /pipe == INVALID_HANDLE_VALUE[\s\S]*EventKind::kError[\s\S]*EventKind::kClosed[\s\S]*napi_release_threadsafe_function/u)
    assert.equal((worker.match(/EventKind::kClosed/gu) ?? []).length, 2, 'pre-connect and connected exits each own one close path')
    assert.doesNotMatch(destroy, /\.join\(|EventKind::kClosed/u)
})

test('Windows connector validates fixed SCM service before bounded demand activation', async () => {
    const source = await readFile(join(projectRoot, 'native/windows-client-addon/openrdx_windows_client.cc'), 'utf8')
    const activation = source.slice(source.indexOf('const char* EnsureServiceRunning'), source.indexOf('HANDLE OpenVerifiedPipe'))
    const openPipe = source.slice(source.indexOf('HANDLE OpenVerifiedPipe'), source.indexOf('void Worker'))

    assert.match(source, /kServiceControlAccess\s*=\s*SERVICE_QUERY_CONFIG \| SERVICE_QUERY_STATUS \| SERVICE_START/u)
    assert.match(activation, /OpenSCManagerW\(nullptr, nullptr, SC_MANAGER_CONNECT\)/u)
    assert.match(activation, /OpenServiceW\([\s\S]*kServiceControlAccess/u)
    assert.match(activation, /ScopedHandle expected_file[\s\S]*FileIdentity expected_identity/u)
    assert.match(activation, /ImmutableServiceConfigMatches\([^;]*expected_identity/u)
    assert.match(activation, /ImmutableServiceConfigMatches[\s\S]*SERVICE_WIN32_OWN_PROCESS[\s\S]*SERVICE_DEMAND_START/u)
    assert.match(activation, /dwCurrentState == SERVICE_STOPPED[\s\S]*StartServiceW/u)
    assert.match(activation, /ERROR_SERVICE_ALREADY_RUNNING/u)
    assert.match(activation, /SERVICE_START_PENDING|SERVICE_STOP_PENDING/u)
    assert.match(activation, /kServiceStartTimeoutMs[\s\S]*service_start_deadline[\s\S]*Sleep\(delay\)/u)
    assert.match(activation, /RunningServiceSnapshotMatches\([^;]*expected_identity/u)
    assert.match(openPipe, /EnsureServiceRunning[\s\S]*WaitNamedPipeW[\s\S]*CreateFileW/u)
})

test('Windows cold activation uses one deadline and retries only delayed pipe appearance', async () => {
    const source = await readFile(join(projectRoot, 'native/windows-client-addon/openrdx_windows_client.cc'), 'utf8')
    const activation = source.slice(source.indexOf('const char* EnsureServiceRunning'), source.indexOf('void Worker'))
    const transientErrors = source.slice(source.indexOf('bool IsTransientPipeAvailabilityError'), source.indexOf('bool CreatePendingIo'))

    assert.match(source, /kNativeActivationTimeoutMs\s*=\s*7'000/u)
    assert.match(transientErrors, /ERROR_FILE_NOT_FOUND[\s\S]*ERROR_PIPE_BUSY[\s\S]*ERROR_SEM_TIMEOUT/u)
    assert.doesNotMatch(transientErrors, /ERROR_ACCESS_DENIED|ERROR_SERVICE_DOES_NOT_EXIST/u)
    assert.match(activation, /activation_deadline/u)
    assert.match(activation, /EnsureServiceRunning\(expected, activation_deadline\)/u)
    assert.match(activation, /ERROR_ACCESS_DENIED[\s\S]*insufficient-permission[\s\S]*IsTransientPipeAvailabilityError/u)
    assert.match(activation, /WaitNamedPipeW\(kPipeName, [^)]+\)[\s\S]*CreateFileW/u)
    assert.match(activation, /VerifyServer[\s\S]*service-identity-unverified/u)
    assert.doesNotMatch(activation, /VerifyServer[\s\S]*(?:continue|Sleep)/u)
})

test('Windows SCM callback owns startup-authorized endpoint creation', async () => {
    const [service, serviceBinary] = await Promise.all([readFile(join(projectRoot, 'native/rdx-service/windows-native/src/service.rs'), 'utf8'), readFile(join(projectRoot, 'native/rdx-service/src/bin/openrdx-hardware.rs'), 'utf8')])
    const registered = service.slice(service.indexOf('fn run_registered_service'), service.indexOf('fn wide_null'))
    const serviceLoop = serviceBinary.slice(serviceBinary.indexOf('fn run_windows_service_generation'), serviceBinary.indexOf('struct StopAwareReader'))

    // The portable production startup seam tests binding/publication order;
    // this integration contract keeps that seam attached to the SCM callback.
    assert.match(registered, /startup::start_endpoint/u)
    assert.match(registered, /NamedPipeManagerEndpointListener::bind\(\s*RegisteredServiceStartup::verify/u)
    assert.match(serviceLoop, /listener:\s*rdx_windows_native::NamedPipeManagerEndpointListener/u)
    assert.doesNotMatch(serviceLoop, /NamedPipeManagerEndpointListener::bind/u)
})

test('Windows service retains its pending pipe across idle polls and later sessions', async () => {
    const [endpoint, serviceBinary] = await Promise.all([readFile(join(projectRoot, 'native/rdx-service/windows-native/src/endpoint.rs'), 'utf8'), readFile(join(projectRoot, 'native/rdx-service/src/bin/openrdx-hardware.rs'), 'utf8')])
    const acceptUntil = endpoint.slice(endpoint.indexOf('pub fn accept_until'), endpoint.indexOf('unsafe impl Send'))
    const serviceLoop = serviceBinary.slice(serviceBinary.indexOf('fn run_windows_service_generation'), serviceBinary.indexOf('struct StopAwareReader'))

    assert.match(acceptUntil, /self\.pending\.as_ref\(\)[\s\S]*accept_native[\s\S]*self\.pending\.take\(\)/u)
    assert.match(serviceLoop, /WindowsAcceptDisposition::Idle => continue/u)
    assert.match(serviceLoop, /NativeError::TimedOut[\s\S]*WindowsAcceptDisposition::Idle/u)
    assert.doesNotMatch(serviceLoop, /NativeError::ResourceLimit\) => return Ok/u)
})

test('Windows service ACL provisioner derives only a live verified installed Manager identity', async () => {
    const source = await readFile(join(projectRoot, 'native/rdx-service/windows-native/src/service_acl.rs'), 'utf8')

    assert.match(source, /QueryFullProcessImageNameW/u)
    assert.match(source, /WinVerifyTrust/u)
    assert.match(source, /WTSGetActiveConsoleSessionId/u)
    assert.match(source, /OpenProcessToken/u)
    assert.match(source, /SetServiceObjectSecurity/u)
    // The closed diagnostic wrapper must still propagate the original strict readback result.
    assert.match(source, /diagnostic\(\s*Stage::ManagerDacl,\s*exact_dacl_matches\([^)]*\),?\s*\)\?/u)
    assert.equal((source.match(/validate_manager_process\(/gu) ?? []).length >= 3, true)
    assert.match(source, /raw_ace_address[\s\S]*checked_add\(size_of::<ACCESS_ALLOWED_ACE>\(\)\)[\s\S]*descriptor_end/u)
    assert.doesNotMatch(source, /ConvertStringSidToSid|LookupAccountName/u)
    assert.doesNotMatch(source, /verify_exact_dacl\([^;]+\.is_ok\(\)/su)
})

test('Windows native client build stages only the fixed opaque addon artifact', () => {
    const paths = getWindowsClientAddonBuildPaths({ root: projectRoot })

    assert.equal(paths.artifactPath, join(projectRoot, 'native/windows-client-addon/build/Release/openrdx_windows_client.node'))
    assert.equal(paths.runtimePath, join(projectRoot, 'out/native/windows/openrdx-windows-client.node'))
})

test('Windows native connector rejects every caller-authored pipe path before addon load', () => {
    const connector = createWindowsNativeEndpointConnector({ addonPath: join(projectRoot, 'fixture.node') })

    assert.throws(() => connector({ path: String.raw`\\.\pipe\attacker`, expectedExecutable: String.raw`C:\Program Files\OpenRDXManager\openrdx-hardware.exe` }), /windows-client-endpoint-invalid/u)
})
