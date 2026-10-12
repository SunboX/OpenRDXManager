// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, posix } from 'node:path'
import test from 'node:test'
import { createInstallerConfiguration, verifyWindowsInstallerToolchain } from '../scripts/installer-config.mjs'

for (const platform of ['darwin', 'win32', 'linux']) {
    test(`installer contains only the matching native runtime on ${platform}`, () => {
        const config = createInstallerConfiguration(platform)
        const folder = { darwin: 'macos', win32: 'windows', linux: 'linux' }[platform]
        assert.equal(config.appId, 'com.openrdx.manager')
        assert.equal(config.extraResources[0].from, `out/native/${folder}`)
        assert.equal(config.extraResources[0].to, `native/${folder}`)
        assert.ok(config.files.includes('src/**/*'))
        assert.ok(config.files.includes('out/preload.cjs'))
        assert.ok(config.files.includes('scripts/mcp-stdio.mjs'), 'Copied configuration must name a shipped bridge')
        assert.equal(config.asar, true)
        for (const bridgeInput of ['scripts/mcp-stdio.mjs', 'src/main/**/*', 'package.json', 'node_modules/**/*']) {
            assert.ok(config.asarUnpack?.includes(bridgeInput), `External Node requires ordinary files for ${bridgeInput}`)
        }
        assert.ok(!config.files.some((entry) => /analysis|original-inputs|test\//.test(entry)))
        assert.ok(config.mac.extraFiles.some((entry) => entry.to === 'Library/LaunchServices/openrdx-hardware'))
        assert.equal(config.nsis.perMachine, true)
        assert.equal(config.npmRebuild, false, 'N-API addons are built separately for the native runner')
        assert.equal(config.artifactName, `OpenRDXManager-\${version}-\${os}-${process.arch}.\${ext}`, 'Linux target-specific architecture aliases must not change release inventory names')
        const hostArchitecture = process.arch === 'arm64' ? 3 : 1
        assert.doesNotThrow(() => config.beforePack({ arch: hostArchitecture }))
        assert.throws(() => config.beforePack({ arch: hostArchitecture === 3 ? 1 : 3 }), /native-installer-architecture-mismatch/)
    })
}

test('Linux installer places the regular manager binary at the native peer identity contract path', async () => {
    const source = await readFile(new URL('../native/rdx-service/linux-native/src/endpoint.rs', import.meta.url), 'utf8')
    // Read the owning contract value, then compare it to the actual installer
    // layout rather than trusting the desktop symlink or its capitalization.
    const declarations = [...source.matchAll(/^const MANAGER_PATH: &str = "([^"]+)";$/gmu)]
    assert.equal(declarations.length, 1)
    const config = createInstallerConfiguration('linux')
    assert.equal(declarations[0][1], posix.join('/opt', config.productName, config.executableName))
})

for (const platform of ['darwin', 'win32']) {
    test(`locally trusted installer disables alternate Electron execution on ${platform}`, () => {
        const config = createInstallerConfiguration(platform)
        assert.equal(config.electronFuses?.runAsNode, false)
        assert.equal(config.electronFuses?.enableNodeOptionsEnvironmentVariable, false)
        assert.equal(config.electronFuses?.enableNodeCliInspectArguments, false)
        assert.equal(config.electronFuses?.enableEmbeddedAsarIntegrityValidation, true)
        assert.equal(config.electronFuses?.onlyLoadAppFromAsar, true)
        assert.equal(typeof config.afterSign, 'function', 'Inventory must pin final executable bytes')
    })
}

test('Windows installer uses fixed machine-wide placement and explicit native setup', () => {
    const config = createInstallerConfiguration('win32')
    assert.equal(config.nsis.allowToChangeInstallationDirectory, false)
    assert.equal(config.nsis.include, 'resources/installer/windows-service.nsh')
    assert.equal(config.nsis.script, 'resources/installer/windows-installer.nsi', 'Protect incoming and uninstaller temporary paths before any plugin loads')
    assert.equal(config.win.signExecutable, false, 'Unsigned resource editing still invokes afterSign in builder 26.17')
    assert.equal(config.toolsets?.nsis, '1.2.1', 'Pin the checksum-verified NSIS 3.12 bundle instead of the legacy bootstrap')
})

test('local Windows setup cannot substitute an unverified NSIS compiler or plugin bundle', () => {
    const context = { electronPlatformName: 'win32', packager: { config: { toolsets: { nsis: '1.2.1' } } } }
    assert.doesNotThrow(() => verifyWindowsInstallerToolchain(context, {}))
    for (const name of ['ELECTRON_BUILDER_NSIS_DIR', 'ELECTRON_BUILDER_NSIS_RESOURCES_DIR', 'CUSTOM_NSIS_RESOURCES']) assert.throws(() => verifyWindowsInstallerToolchain(context, { [name]: '/unverified/toolset' }), /local-installer-nsis-toolchain-invalid/u)
    for (const nsis of [{ customNsisBinary: {} }, { customNsisResources: {} }]) assert.throws(() => verifyWindowsInstallerToolchain({ ...context, packager: { config: { toolsets: { nsis: '1.2.1' }, nsis } } }, {}), /local-installer-nsis-toolchain-invalid/u)
    assert.throws(() => verifyWindowsInstallerToolchain({ ...context, packager: { config: { toolsets: { nsis: '0.0.0' } } } }, {}), /local-installer-nsis-toolchain-invalid/u)
})

test('macOS packages only maintained runtime helpers even if native build output contains stale verification binaries', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-native-runtime-filter-'))
    try {
        const source = join(root, 'native')
        const destination = join(root, 'packaged-native')
        await mkdir(source)
        const maintained = ['rdxctl', 'openrdx-hardware', 'openrdx-local-install', 'openrdx-macos-client.node', 'openrdx-service-management.node']
        for (const name of [...maintained, 'openrdx-readiness-verifier', 'local-trust-test-fixture']) await writeFile(join(source, name), 'disposable-build-output')
        const { FileMatcher, copyFiles } = createRequire(import.meta.url)('app-builder-lib/out/fileMatcher.js')
        const runtime = createInstallerConfiguration('darwin').extraResources[0]
        // Use builder's real copy operation: an absent filter would also ship the stale fixtures.
        await copyFiles([new FileMatcher(source, destination, (value) => value, runtime.filter)], undefined, false)
        assert.deepEqual((await readdir(destination)).sort(), maintained.sort())
        assert.equal(createInstallerConfiguration('win32').extraResources[0].filter, undefined)
        assert.equal(createInstallerConfiguration('linux').extraResources[0].filter, undefined)
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('local macOS bundle cannot advertise an SMAppService daemon alongside the standalone PKG service', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-local-bundle-service-'))
    try {
        const contents = join(root, 'app/Contents')
        const { FileMatcher, copyFiles } = createRequire(import.meta.url)('app-builder-lib/out/fileMatcher.js')
        for (const entry of createInstallerConfiguration('darwin').mac.extraFiles) {
            const source = join(root, entry.from)
            await mkdir(join(source, '..'), { recursive: true })
            await writeFile(source, 'controlled-runtime-resource')
            await copyFiles([new FileMatcher(source, join(contents, entry.to), (value) => value)], undefined, false)
        }
        assert.deepEqual(await readdir(join(contents, 'Library')), ['LaunchServices'])
        assert.equal(await readFile(join(contents, 'Library/LaunchServices/openrdx-hardware'), 'utf8'), 'controlled-runtime-resource')
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})
