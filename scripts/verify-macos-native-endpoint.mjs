// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { access, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { createRequire } from 'node:module'
import { createConnection } from 'node:net'
import { once } from 'node:events'
import { setTimeout as delay } from 'node:timers/promises'
import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)
const root = fileURLToPath(new URL('..', import.meta.url))

/**
 * Run real macOS audit-token/code/path checks with an ad-hoc-sealed local fixture.
 * This compiles only generated test output and never installs or contacts devices.
 * @returns {Promise<{skipped: boolean, output?: string}>} Native assertion evidence.
 */
export async function verifyMacOsNativeEndpoint() {
    if (process.platform !== 'darwin') return { skipped: true }
    const xcodeSdk = '/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk'
    let sdk = process.env.SDKROOT
    if (!sdk) {
        try {
            await access(xcodeSdk)
            sdk = xcodeSdk
        } catch {
            sdk = (await execFileAsync('/usr/bin/xcrun', ['--sdk', 'macosx', '--show-sdk-path'])).stdout.trim()
        }
    }
    const output = join(root, 'out/verification/macos-native/endpoint-peer-verification-test')
    await mkdir(join(root, 'out/verification/macos-native'), { recursive: true })
    await execFileAsync('/usr/bin/xcrun', ['clang', '-std=c17', '-Wall', '-Wextra', '-Werror', '-DRDX_MACOS_ENDPOINT_TEST_HOOKS=1', '-DOPENRDX_MACOS_TEAM_ID="ABCD123456"', '-I', join(root, 'native/rdx-service/native/macos'), join(root, 'native/macos-client-addon/endpoint_identity_test.c'), join(root, 'native/rdx-service/native/macos/rdx_endpoint_identity.c'), join(root, 'native/rdx-service/native/macos/rdx_endpoint.c'), '-framework', 'Security', '-framework', 'CoreFoundation', '-lbsm', '-lproc', '-o', output], {
        env: { ...process.env, SDKROOT: sdk },
        maxBuffer: 1024 * 1024
    })
    await execFileAsync('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', 'com.openrdx.manager', output])
    const result = await execFileAsync(output, [], { timeout: 10_000, maxBuffer: 1024 * 1024 })
    const budgetFixture = join(root, 'out/verification/macos-native/verification-budget-test')
    await execFileAsync('/usr/bin/xcrun', ['clang++', '-std=c++20', '-Wall', '-Wextra', '-Werror', join(root, 'native/macos-client-addon/verification_budget_test.cc'), '-o', budgetFixture], { env: { ...process.env, SDKROOT: sdk } })
    const budget = await execFileAsync(budgetFixture, [], { timeout: 5_000, maxBuffer: 1024 * 1024 })
    const inheritedHelper = join(root, 'out/verification/macos-native/inherited-listener-helper')
    const inheritedTest = join(root, 'out/verification/macos-native/inherited-listener-test')
    const environment = { ...process.env, SDKROOT: sdk }
    await execFileAsync('/usr/bin/xcrun', ['clang', '-std=c17', '-Wall', '-Wextra', '-Werror', join(root, 'native/macos-client-addon/inherited_listener_helper.c'), '-o', inheritedHelper], { env: environment })
    await execFileAsync('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', 'com.openrdx.hardware', inheritedHelper])
    await execFileAsync('/usr/bin/xcrun', ['clang', '-std=c17', '-Wall', '-Wextra', '-Werror', '-I', join(root, 'native/rdx-service/native/macos'), join(root, 'native/macos-client-addon/inherited_listener_test.c'), join(root, 'native/rdx-service/native/macos/rdx_endpoint_identity.c'), '-framework', 'Security', '-framework', 'CoreFoundation', '-lbsm', '-lproc', '-o', inheritedTest], { env: environment })
    await execFileAsync('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', 'com.openrdx.manager', inheritedTest])
    const inherited = await execFileAsync(inheritedTest, [inheritedHelper], { timeout: 10_000, maxBuffer: 1024 * 1024 })
    const launchd = await verifyActualLaunchdListener(root, environment)
    return { skipped: false, output: `${result.stdout.trim()}; ${budget.stdout.trim()}; ${inherited.stdout.trim()}; ${launchd}` }
}

/**
 * Exercise real own-job launchd activation in a temporary ordinary-user domain.
 * Executable, plist, log and socket stay outside protected Documents/TCC input;
 * bootout and cleanup execute on every path. No production registration occurs.
 * @param {string} project - Source root.
 * @param {NodeJS.ProcessEnv} environment - Compiler environment.
 * @returns {Promise<string>} Bounded native assertion evidence.
 */
async function verifyActualLaunchdListener(project, environment) {
    const fixture = await mkdtemp('/private/tmp/openrdx-launchd-regression-')
    const label = `com.openrdx.test.activation.${randomUUID()}`
    const socketPath = `/tmp/${label}.sock`
    // This separate ordinary-user fixture models a foreign legacy job. The
    // local acceptance flow must leave its registration and socket untouched.
    const legacyLabel = `com.openrdx.test.legacy.${randomUUID()}`
    const legacySocketPath = `/tmp/${legacyLabel}.sock`
    const legacyPlistPath = join(fixture, 'legacy.plist')
    const helper = join(fixture, 'helper')
    const plistPath = join(fixture, 'fixture.plist')
    const logPath = join(fixture, 'fixture.log')
    const uid = process.getuid()
    let domain = `gui/${uid}`
    const plist = createRequire(import.meta.url)('plist')
    let registered = false
    let legacyRegistered = false
    let socket
    try {
        try {
            await execFileAsync('/bin/launchctl', ['print', domain])
        } catch {
            domain = `user/${uid}`
        }
        await execFileAsync('/usr/bin/xcrun', ['clang', '-std=c17', '-Wall', '-Wextra', '-Werror', '-DRDX_MACOS_ENDPOINT_TEST_HOOKS=1', '-I', join(project, 'native/rdx-service/native/macos'), join(project, 'native/macos-client-addon/launchd_listener_helper.c'), join(project, 'native/rdx-service/native/macos/rdx_endpoint.c'), join(project, 'native/rdx-service/native/macos/rdx_endpoint_identity.c'), '-framework', 'Security', '-framework', 'CoreFoundation', '-lbsm', '-lproc', '-o', helper], { env: environment })
        await execFileAsync('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', 'com.openrdx.fixture', helper])
        await writeFile(legacyPlistPath, plist.build({ Label: legacyLabel, ProgramArguments: [helper], Sockets: { Listener: { SockPathName: legacySocketPath, SockPathMode: 384 } }, StandardErrorPath: join(fixture, 'legacy.log') }), { mode: 0o600 })
        await execFileAsync('/bin/launchctl', ['bootstrap', domain, legacyPlistPath])
        legacyRegistered = true
        await writeFile(plistPath, plist.build({ Label: label, ProgramArguments: [helper], Sockets: { Listener: { SockPathName: socketPath, SockPathMode: 384 } }, StandardErrorPath: logPath }), { mode: 0o600 })
        await execFileAsync('/bin/launchctl', ['bootstrap', domain, plistPath])
        registered = true
        const deadline = Date.now() + 5_000
        while (true) {
            try {
                await access(socketPath)
                await access(legacySocketPath)
                break
            } catch {
                if (Date.now() >= deadline) throw new Error('launchd-fixture-activation-timeout')
                await delay(20)
            }
        }
        const remaining = deadline - Date.now()
        if (remaining <= 0) throw new Error('launchd-fixture-connect-timeout')
        const legacyBefore = await lstat(legacySocketPath)
        socket = createConnection(socketPath)
        await once(socket, 'connect', { signal: AbortSignal.timeout(remaining) })
        // The fixture never reads/sends protocol bytes; only accept() is tested.
        while (true) {
            let evidence = ''
            try {
                evidence = await readFile(logPath, 'utf8')
            } catch (error) {
                // launchd can publish the socket before creating its stderr file.
                // Only that creation race may retry; permissions/IO errors fail.
                if (error.code !== 'ENOENT') throw error
            }
            if (evidence.includes('launchd listener accepted before protocol bytes')) {
                if (!evidence.includes('launchd listener descriptor: valid=true')) throw new Error('launchd-fixture-descriptor-invalid')
                await execFileAsync('/bin/launchctl', ['print', `${domain}/${legacyLabel}`])
                const legacyAfter = await lstat(legacySocketPath)
                if (!legacyAfter.isSocket() || legacyBefore.dev !== legacyAfter.dev || legacyBefore.ino !== legacyAfter.ino) throw new Error('launchd-fixture-legacy-namespace-changed')
                return 'actual launchd listener: private bind address validated and accepted before protocol bytes; isolated legacy job/socket preserved through acceptance'
            }
            if (Date.now() >= deadline) throw new Error(`launchd-fixture-accept-timeout: ${evidence.slice(0, 512)}`)
            await delay(20)
        }
    } finally {
        socket?.destroy()
        try {
            if (registered) await execFileAsync('/bin/launchctl', ['bootout', `${domain}/${label}`])
        } finally {
            try {
                // Cleanup only this test's uniquely named owned legacy fixture,
                // after the preservation assertions; never a installed job.
                if (legacyRegistered) await execFileAsync('/bin/launchctl', ['bootout', `${domain}/${legacyLabel}`])
            } finally {
                await rm(socketPath, { force: true })
                await rm(legacySocketPath, { force: true })
                await rm(fixture, { recursive: true, force: true })
            }
        }
    }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const result = await verifyMacOsNativeEndpoint()
        process.stdout.write(`${JSON.stringify(result)}\n`)
    } catch {
        process.stderr.write('macos-native-endpoint-verification-failed\n')
        process.exitCode = 1
    }
}
