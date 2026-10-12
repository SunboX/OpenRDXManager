// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { access, mkdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
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
    const output = join(root, 'out/native/macos/endpoint-peer-verification-test')
    await mkdir(join(root, 'out/native/macos'), { recursive: true })
    await execFileAsync('/usr/bin/xcrun', ['clang', '-std=c17', '-Wall', '-Wextra', '-Werror', '-DRDX_MACOS_ENDPOINT_TEST_HOOKS=1', '-DOPENRDX_MACOS_TEAM_ID="ABCD123456"', '-I', join(root, 'native/rdx-service/native/macos'), join(root, 'native/macos-client-addon/endpoint_identity_test.c'), join(root, 'native/rdx-service/native/macos/rdx_endpoint_identity.c'), '-framework', 'Security', '-framework', 'CoreFoundation', '-lbsm', '-o', output], {
        env: { ...process.env, SDKROOT: sdk },
        maxBuffer: 1024 * 1024
    })
    await execFileAsync('/usr/bin/codesign', ['--force', '--sign', '-', '--identifier', 'com.openrdx.manager', output])
    const result = await execFileAsync(output, [], { timeout: 10_000, maxBuffer: 1024 * 1024 })
    return { skipped: false, output: result.stdout.trim() }
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
