// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { chmod, copyFile, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { promisify } from 'node:util'
import { createRuntimeInventory, verifyRuntimeInventory } from './local-trust-inventory.mjs'
import { normalizeMacOsPackageScriptOwners } from './macos-package-ownership.mjs'
import { buildWindowsRemover } from './build-windows-remover.mjs'

const execute = promisify(execFile)
const require = createRequire(import.meta.url)
const { getNsisElevatePath } = require('app-builder-lib/out/toolsets/windows.js')
const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const packages = new Set()

/** @param {object} context - Native electron-builder pack context. @returns {string} Final packaged application root. */
function runtimeRoot(context) {
    return context.electronPlatformName === 'darwin' ? join(context.appOutDir, 'OpenRDXManager.app') : context.appOutDir
}

/**
 * Sets the helper's explicit identity before electron-builder seals the app.
 * @param {object} context - Native pack context; Linux/Windows have no work here.
 * @returns {Promise<void>} Resolves after the fixed nested helper is sealed.
 */
export async function prepareLocalTrustSeal(context) {
    if (context.electronPlatformName !== 'darwin') return
    await execute('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', '--options', 'runtime', '--identifier', 'com.openrdx.hardware', join(runtimeRoot(context), 'Contents/Library/LaunchServices/openrdx-hardware')])
}

/**
 * Builds the root-only macOS payload without modifying the signed application.
 * Installer scripts and CLI run during installation, never during packaging.
 * @param {object} context - Final signed macOS build context.
 * @param {object} inventory - Strict final application inventory.
 * @returns {Promise<string>} Unsigned standalone PKG artifact path.
 */
async function buildMacOsLocalPackage(context, inventory) {
    const architecture = { 1: 'x64', 3: 'arm64' }[context.arch]
    if (!architecture) throw new Error('local-installer-architecture-invalid')
    const stage = join(projectRoot, 'out', `local-pkg-${architecture}`)
    const payload = join(stage, 'payload')
    const scripts = join(stage, 'scripts')
    const app = runtimeRoot(context)
    const trust = join(payload, 'Library/Application Support/OpenRDXManager/LocalTrust')
    const helpers = join(payload, 'Library/PrivilegedHelperTools')
    const daemons = join(payload, 'Library/LaunchDaemons')
    const installerSource = join(projectRoot, 'resources/installer/macos')
    const cli = join(app, 'Contents/Resources/native/macos/openrdx-local-install')
    await rm(stage, { recursive: true, force: true })
    for (const path of [join(payload, 'Applications'), trust, helpers, daemons, scripts]) await mkdir(path, { recursive: true, mode: 0o755 })
    await cp(app, join(payload, 'Applications/OpenRDXManager.app'), { recursive: true, dereference: false, verbatimSymlinks: true })
    await copyFile(join(app, 'Contents/Library/LaunchServices/openrdx-hardware'), join(helpers, 'openrdx-hardware'))
    await chmod(join(helpers, 'openrdx-hardware'), 0o755)
    await copyFile(cli, join(trust, 'openrdx-local-install'))
    await copyFile(cli, join(scripts, 'openrdx-local-install'))
    await chmod(join(trust, 'openrdx-local-install'), 0o755)
    await chmod(join(scripts, 'openrdx-local-install'), 0o755)
    await writeFile(join(trust, 'pending-runtime.json'), `${JSON.stringify(inventory)}\n`, { mode: 0o600 })
    // The elevated preinstall records this candidate as transaction history so
    // interrupted first installs can be repaired without enabling authentication.
    await writeFile(join(scripts, 'pending-runtime.json'), `${JSON.stringify(inventory)}\n`, { mode: 0o600 })
    await copyFile(join(installerSource, 'com.openrdx.hardware.plist'), join(daemons, 'com.openrdx.hardware.plist'))
    await chmod(join(daemons, 'com.openrdx.hardware.plist'), 0o644)
    for (const script of ['preinstall', 'postinstall']) {
        await copyFile(join(installerSource, script), join(scripts, script))
        await chmod(join(scripts, script), 0o755)
    }
    await copyFile(join(installerSource, 'uninstall.sh'), join(trust, 'uninstall.sh'))
    await chmod(join(trust, 'uninstall.sh'), 0o755)
    // Pin the copied payload as well: copy implementation and post-sign hooks
    // must not alter a framework link, ASAR or code signature before archiving.
    await verifyRuntimeInventory({ root: join(payload, 'Applications/OpenRDXManager.app'), inventory })
    const components = join(stage, 'components.plist')
    await execute('/usr/bin/pkgbuild', ['--analyze', '--root', payload, components])
    const conversion = await execute('/usr/bin/plutil', ['-convert', 'json', '-o', '-', components])
    const configuration = JSON.parse(conversion.stdout)
    for (const component of configuration) {
        component.BundleIsRelocatable = false
        component.BundleHasStrictIdentifier = true
        component.BundleOverwriteAction = 'upgrade'
    }
    await writeFile(components, JSON.stringify(configuration))
    await execute('/usr/bin/plutil', ['-convert', 'xml1', components])
    const version = context.packager.appInfo.version
    const output = join(context.outDir, `OpenRDXManager-${version}-mac-${architecture}.pkg`)
    await execute('/usr/bin/pkgbuild', ['--root', payload, '--component-plist', components, '--identifier', 'com.openrdx.manager.local-install', '--version', version, '--install-location', '/', '--ownership', 'recommended', '--scripts', scripts, output], { maxBuffer: 16 * 1024 * 1024 })
    await normalizeMacOsPackageScriptOwners({ packagePath: output, scripts, scratch: join(stage, 'root-script-package') })
    packages.add(output)
    return output
}

/**
 * Records final resource-edited/signed bytes before any distributable is archived.
 * Windows sets signExecutable=false while retaining resource editing; builder
 * 26.17 then invokes this hook even without public signing credentials.
 * @param {object} context - Electron-builder afterSign context.
 * @returns {Promise<void>} Resolves after final inventory and macOS PKG creation.
 */
export async function finalizeLocalTrustRuntime(context) {
    const platform = { darwin: 'macos', win32: 'windows' }[context.electronPlatformName]
    if (!platform) return
    const root = runtimeRoot(context)
    if (platform === 'windows') {
        await stageWindowsElevationHelper({ root })
        await buildWindowsRemover({ root, appId: context.packager.appInfo.id, version: context.packager.appInfo.version, guid: context.packager.config.nsis?.guid })
    }
    if (platform === 'macos') {
        // Explicitly reseal the changed nested helper, then only its parent.
        // Deep strict verification ensures the rest of builder's nested seals
        // remain valid; the inventory is always generated after this last edit.
        await prepareLocalTrustSeal(context)
        await execute('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', '--options', 'runtime', '--preserve-metadata=identifier,entitlements,requirements', root])
        await execute('/usr/bin/codesign', ['--verify', '--deep', '--strict', root])
    }
    const inventory = await createRuntimeInventory({ root, platform })
    if (platform === 'windows') {
        const destination = join(root, 'resources/local-trust/runtime.json')
        await mkdir(dirname(destination), { recursive: true })
        await writeFile(destination, `${JSON.stringify(inventory)}\n`)
        const bootstrap = join(projectRoot, 'out/nsis-local-trust')
        await mkdir(bootstrap, { recursive: true })
        await writeFile(join(bootstrap, 'pending-runtime.json'), `${JSON.stringify(inventory)}\n`)
    } else {
        await buildMacOsLocalPackage(context, inventory)
    }
    await verifyRuntimeInventory({ root, inventory })
}

/**
 * Pins the same helper NSIS adds after afterSign in electron-builder 26.17.
 * Staging first also keeps ZIP and unpacked runtime inventory identical.
 * @param {{root: string, resolveHelper?: Function}} options - Build root and fixed-tool resolver.
 * @returns {Promise<void>} Resolves after copying the checksum-verified bundle file.
 */
export async function stageWindowsElevationHelper({ root, resolveHelper = () => getNsisElevatePath('1.2.1') }) {
    const source = await resolveHelper()
    const destination = join(root, 'resources/elevate.exe')
    await mkdir(dirname(destination), { recursive: true })
    await copyFile(source, destination)
}

/** @returns {Promise<string[]>} Additional standalone packages emitted by the final signed-runtime hook. */
export async function localTrustArtifacts() {
    return [...packages]
}

/**
 * Verifies final byte pins for a Windows packaged directory.
 * @param {string} root - Controlled build artifact root.
 * @returns {Promise<void>} Resolves after strict inventory comparison.
 */
export async function verifyWindowsPackagedInventory(root) {
    const inventory = JSON.parse(await readFile(join(resolve(root), 'resources/local-trust/runtime.json'), 'utf8'))
    await verifyRuntimeInventory({ root, inventory })
}
