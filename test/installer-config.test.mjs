// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { posix } from 'node:path'
import test from 'node:test'
import { createInstallerConfiguration } from '../scripts/installer-config.mjs'

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
