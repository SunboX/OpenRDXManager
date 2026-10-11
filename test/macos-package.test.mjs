// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

import { getMacOsPackagePaths, packageMacOsApplication, resolveMacOsSigningIdentity } from '../scripts/package-macos.mjs'

const execFileAsync = promisify(execFile)

/** Creates one regular file and its parents. @param {string} path - Output path. @param {string} contents - File contents. @returns {Promise<void>} Resolves after creation. */
async function createFile(path, contents = 'fixture') {
    await mkdir(join(path, '..'), { recursive: true })
    await writeFile(path, contents)
}

/** Creates a minimal synthetic project and Electron bundle for assembly behavior. @param {string} projectRoot - Temporary root. @returns {Promise<void>} Resolves after fixture creation. */
async function createSyntheticProject(projectRoot) {
    const electronContents = join(projectRoot, 'node_modules', 'electron', 'dist', 'Electron.app', 'Contents')
    await createFile(join(electronContents, 'MacOS', 'Electron'))
    await chmod(join(electronContents, 'MacOS', 'Electron'), 0o755)
    await createFile(join(electronContents, 'Info.plist'), `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>Electron</string><key>CFBundleIdentifier</key><string>com.github.Electron</string><key>CFBundleName</key><string>Electron</string><key>CFBundleDisplayName</key><string>Electron</string><key>CFBundleIconFile</key><string>electron.icns</string><key>CFBundleShortVersionString</key><string>44.0.0</string><key>CFBundleVersion</key><string>44.0.0</string></dict></plist>`)
    await createFile(join(electronContents, 'Resources', 'default_app.asar'))
    await createFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'openrdxmanager', productName: 'OpenRDXManager', version: '0.1.0', main: 'src/main.mjs', type: 'module', dependencies: { '@fontsource/inter': '1', '@fontsource/oxanium': '1', '@phosphor-icons/web': '1', zod: '1' } }))
    await createFile(join(projectRoot, 'src', 'main.mjs'), 'export {}\n')
    await createFile(join(projectRoot, 'resources', 'icons', 'app-icon.icns'), 'icns-fixture')
    await createFile(join(projectRoot, 'resources', 'icons', 'app-icon.ico'), 'ico-fixture')
    await createFile(join(projectRoot, 'resources', 'icons', 'app-icon.png'), 'png-fixture')
    await createFile(join(projectRoot, 'out', 'preload.cjs'), 'module.exports = {}\n')
    for (const dependency of ['@fontsource/inter', '@fontsource/oxanium', '@phosphor-icons/web', 'zod']) {
        await createFile(join(projectRoot, 'node_modules', dependency, 'package.json'), JSON.stringify({ name: dependency }))
    }
    await createFile(join(projectRoot, 'out', 'native', 'macos', 'openrdx-hardware'))
    await chmod(join(projectRoot, 'out', 'native', 'macos', 'openrdx-hardware'), 0o755)
    await createFile(join(projectRoot, 'out', 'native', 'macos', 'openrdx-service-management.node'))
    await createFile(join(projectRoot, 'native', 'rdx-service', 'resources', 'macos', 'com.openrdx.hardware.plist'), '<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.openrdx.hardware</string></dict></plist>')
}

test('assembles one signed macOS helper and the fixed packaged runtime layout', { skip: process.platform !== 'darwin' }, async (context) => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'openrdx-package-project-'))
    const outputRoot = await mkdtemp(join(tmpdir(), 'openrdx-package-output-'))
    context.after(async () => Promise.all([rm(projectRoot, { force: true, recursive: true }), rm(outputRoot, { force: true, recursive: true })]))
    await createSyntheticProject(projectRoot)
    const invocations = []

    /** Executes real copy/plist tools while containing signing to an observable fake. @param {string} command - Absolute executable. @param {string[]} args - Arguments. @param {object} options - Exec options. @returns {Promise<object>} Process result. */
    async function execute(command, args, options) {
        invocations.push([command, ...args])
        if (command === '/usr/bin/codesign') return { stdout: '', stderr: '' }
        return execFileAsync(command, args, options)
    }

    const result = await packageMacOsApplication({ execFileImpl: execute, outputRoot, projectRoot, signingIdentity: 'TEST SIGNING IDENTITY' })
    const paths = getMacOsPackagePaths({ outputRoot, projectRoot })
    assert.deepEqual(result, { appPath: paths.appPath })
    assert.equal((await lstat(paths.helperPath)).isFile(), true)
    assert.equal((await lstat(paths.addonPath)).isFile(), true)
    assert.equal((await lstat(paths.daemonPlistPath)).isFile(), true)
    assert.equal((await lstat(join(paths.appResourcesPath, 'app', 'src', 'main.mjs'))).isFile(), true)
    assert.equal((await lstat(join(paths.appResourcesPath, 'OpenRDXManager.icns'))).isFile(), true)
    assert.equal((await lstat(join(paths.appResourcesPath, 'app', 'resources', 'icons', 'app-icon.png'))).isFile(), true)
    await assert.rejects(lstat(join(paths.appResourcesPath, 'native', 'macos', 'openrdx-hardware')), /ENOENT/)
    const infoPlist = await readFile(join(paths.appContentsPath, 'Info.plist'), 'utf8')
    assert.match(infoPlist, /com\.openrdx\.manager/)
    assert.match(infoPlist, /OpenRDXManager\.icns/)
    assert.equal(
        invocations.some((call) => call[0] === '/usr/bin/codesign' && call.includes('--verify') && call.includes('--strict')),
        true
    )
})

test('rejects ambiguous signing and output configuration before assembly', async () => {
    const absoluteRoot = join(tmpdir(), 'openrdx-package-invalid')
    assert.throws(() => getMacOsPackagePaths({ projectRoot: 'relative', outputRoot: absoluteRoot }), /macos-package-root-invalid/)
    await assert.rejects(packageMacOsApplication({ projectRoot: absoluteRoot, outputRoot: absoluteRoot, signingIdentity: '' }), /macos-signing-identity-invalid/)
    await assert.rejects(packageMacOsApplication({ projectRoot: absoluteRoot, outputRoot: 'relative', signingIdentity: 'IDENTITY' }), /macos-package-root-invalid/)
})

test('resolves one explicit code-signing identity and its exact team', async () => {
    const stdout = `  1) 43763AAF6D77200852574DAFCD5BFE5B560263B9 "Apple Distribution: GEWA music GmbH (C79TQ55BDS)"\n  2) 367A0478069F2EDA1D6A0CF8C5568218FAE60C5B "Apple Development: Andre Fiedler (7UXAQ487HP)"\n     2 valid identities found\n`
    const execute = async () => ({ stdout, stderr: '' })
    const resolveTeam = async () => 'C79TQ55BDS'

    assert.deepEqual(await resolveMacOsSigningIdentity('367A0478069F2EDA1D6A0CF8C5568218FAE60C5B', execute, resolveTeam), { hash: '367A0478069F2EDA1D6A0CF8C5568218FAE60C5B', name: 'Apple Development: Andre Fiedler (7UXAQ487HP)', teamId: 'C79TQ55BDS' })
    assert.deepEqual(await resolveMacOsSigningIdentity('Apple Distribution: GEWA music GmbH (C79TQ55BDS)', execute, resolveTeam), { hash: '43763AAF6D77200852574DAFCD5BFE5B560263B9', name: 'Apple Distribution: GEWA music GmbH (C79TQ55BDS)', teamId: 'C79TQ55BDS' })
    await assert.rejects(resolveMacOsSigningIdentity('missing', execute, resolveTeam), /macos-signing-identity-not-found/)
    await assert.rejects(resolveMacOsSigningIdentity('', execute, resolveTeam), /macos-signing-identity-invalid/)
})
