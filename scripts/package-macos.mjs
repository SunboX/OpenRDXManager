// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { randomUUID, X509Certificate } from 'node:crypto'
import { chmod, lstat, mkdir, readFile, rename, rm } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

import { buildMacOsServiceManagementAddon } from './build-macos-service-management.mjs'
import { buildNativeService } from './build-native-service.mjs'

const execFileAsync = promisify(execFile)
const defaultProjectRoot = fileURLToPath(new URL('..', import.meta.url))
const runtimeDependencies = Object.freeze(['@fontsource/inter', '@fontsource/oxanium', '@phosphor-icons/web', 'zod'])

/**
 * Resolves one caller-selected valid code-signing identity and its certificate team.
 * @param {string} signingIdentity - Exact SHA-1 hash or displayed identity name.
 * @param {Function} [execFileImpl] - Injectable process runner.
 * @param {Function} [resolveTeamIdImpl] - Injectable certificate subject resolver.
 * @returns {Promise<{hash: string, name: string, teamId: string}>} Exact identity evidence.
 * @throws {TypeError|Error} When selection is invalid, absent, ambiguous, or lacks a team.
 */
export async function resolveMacOsSigningIdentity(signingIdentity, execFileImpl = execFileAsync, resolveTeamIdImpl = resolveCertificateTeamId) {
    if (typeof signingIdentity !== 'string' || signingIdentity.length < 1 || signingIdentity.length > 256 || /[\u0000-\u001f\u007f]/u.test(signingIdentity)) {
        throw new TypeError('macos-signing-identity-invalid')
    }
    const result = await execFileImpl('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning'], { encoding: 'utf8', maxBuffer: 1024 * 1024 })
    if (typeof result?.stdout !== 'string' || Buffer.byteLength(result.stdout, 'utf8') > 1024 * 1024) throw new Error('macos-signing-identity-query-invalid')
    const matches = []
    const identityPattern = /^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"\s*$/gmu
    for (const match of result.stdout.matchAll(identityPattern)) {
        const [, hash, name] = match
        if (signingIdentity === hash || signingIdentity === name) matches.push({ hash, name })
    }
    if (matches.length !== 1) throw new Error('macos-signing-identity-not-found')
    const teamId = await resolveTeamIdImpl(matches[0].name, execFileImpl)
    if (typeof teamId !== 'string' || !/^[A-Z0-9]{10}$/u.test(teamId)) throw new Error('macos-signing-team-unavailable')
    return { ...matches[0], teamId }
}

/**
 * Reads the actual certificate subject instead of inferring authority from a
 * human-readable identity label suffix.
 * @param {string} identityName - Exact selected identity name.
 * @param {Function} execFileImpl - Controlled child-process adapter.
 * @returns {Promise<string>} Exact ten-character certificate organization unit.
 */
async function resolveCertificateTeamId(identityName, execFileImpl) {
    let result
    try {
        result = await execFileImpl('/usr/bin/security', ['find-certificate', '-c', identityName, '-p'], { encoding: 'utf8', maxBuffer: 1024 * 1024 })
    } catch {
        throw new Error('macos-signing-certificate-not-found')
    }
    let subject
    try {
        subject = new X509Certificate(result.stdout).subject
    } catch {
        throw new Error('macos-signing-certificate-invalid')
    }
    const teamId = /(?:^|\n)OU=([A-Z0-9]{10})(?:\n|$)/u.exec(subject)?.[1]
    if (teamId === undefined) throw new Error('macos-signing-team-unavailable')
    return teamId
}

/**
 * Resolves every fixed input and output used by macOS packaging.
 * @param {{projectRoot: string, outputRoot: string}} options - Absolute roots.
 * @returns {object} Frozen package path map.
 * @throws {TypeError} When either root is ambiguous.
 */
export function getMacOsPackagePaths(options) {
    if (typeof options?.projectRoot !== 'string' || typeof options?.outputRoot !== 'string' || !isAbsolute(options.projectRoot) || !isAbsolute(options.outputRoot)) {
        throw new TypeError('macos-package-root-invalid')
    }
    const projectRoot = resolve(options.projectRoot)
    const outputRoot = resolve(options.outputRoot)
    if (projectRoot === outputRoot) throw new TypeError('macos-package-root-invalid')
    const appPath = join(outputRoot, 'OpenRDXManager.app')
    const appContentsPath = join(appPath, 'Contents')
    const appResourcesPath = join(appContentsPath, 'Resources')
    return Object.freeze({
        projectRoot,
        outputRoot,
        appPath,
        appContentsPath,
        appResourcesPath,
        helperPath: join(appContentsPath, 'Library', 'LaunchServices', 'openrdx-hardware'),
        daemonPlistPath: join(appContentsPath, 'Library', 'LaunchDaemons', 'com.openrdx.hardware.plist'),
        addonPath: join(appResourcesPath, 'native', 'macos', 'openrdx-service-management.node')
    })
}

/**
 * Verifies one fixed source as a regular non-link file.
 * @param {string} path - Absolute source path.
 * @returns {Promise<void>} Resolves after validation.
 * @throws {Error} When the source is absent or unsafe.
 */
async function verifyRegularFile(path) {
    const metadata = await lstat(path)
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('macos-package-source-invalid')
}

/**
 * Verifies one fixed source as a non-link directory.
 * @param {string} path - Absolute source path.
 * @returns {Promise<void>} Resolves after validation.
 * @throws {Error} When the source is absent or unsafe.
 */
async function verifyDirectory(path) {
    const metadata = await lstat(path)
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error('macos-package-source-invalid')
}

/**
 * Runs `ditto` for one fixed source/destination pair.
 * @param {Function} execute - Injected process runner.
 * @param {string} source - Verified source.
 * @param {string} destination - Controlled destination.
 * @returns {Promise<void>} Resolves after copy.
 */
async function copyWithDitto(execute, source, destination) {
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 })
    await execute('/usr/bin/ditto', [source, destination], { maxBuffer: 16 * 1024 * 1024 })
}

/**
 * Updates one existing application property-list string.
 * @param {Function} execute - Injected process runner.
 * @param {string} plistPath - Controlled application plist.
 * @param {string} key - Fixed property-list key.
 * @param {string} value - Validated value.
 * @returns {Promise<void>} Resolves after update.
 */
async function setPlistString(execute, plistPath, key, value) {
    await execute('/usr/libexec/PlistBuddy', ['-c', `Set :${key} ${value}`, plistPath], { maxBuffer: 1024 * 1024 })
}

/**
 * Assembles and locally signs the fixed macOS application bundle.
 * @param {{projectRoot?: string, outputRoot: string, signingIdentity: string, execFileImpl?: Function}} options - Controlled package inputs.
 * @returns {Promise<{appPath: string}>} Published application path.
 * @throws {TypeError|Error} For invalid configuration, artifacts, or signing.
 */
export async function packageMacOsApplication(options) {
    if (typeof options?.signingIdentity !== 'string' || options.signingIdentity.length < 1 || options.signingIdentity.length > 256 || /[\u0000-\u001f\u007f]/u.test(options.signingIdentity)) {
        throw new TypeError('macos-signing-identity-invalid')
    }
    const paths = getMacOsPackagePaths({ projectRoot: options.projectRoot ?? defaultProjectRoot, outputRoot: options.outputRoot })
    if (process.platform !== 'darwin') throw new Error('macos-package-unsupported-platform')
    const packageMetadataPath = join(paths.projectRoot, 'package.json')
    const sourceAppPath = join(paths.projectRoot, 'node_modules', 'electron', 'dist', 'Electron.app')
    const sourceHelperPath = join(paths.projectRoot, 'out', 'native', 'macos', 'openrdx-hardware')
    const sourceAddonPath = join(paths.projectRoot, 'out', 'native', 'macos', 'openrdx-service-management.node')
    const sourceDaemonPlistPath = join(paths.projectRoot, 'native', 'rdx-service', 'resources', 'macos', 'com.openrdx.hardware.plist')
    const sourceIconDirectory = join(paths.projectRoot, 'resources', 'icons')
    const sourceMacOsIconPath = join(sourceIconDirectory, 'app-icon.icns')
    await Promise.all([verifyDirectory(sourceAppPath), verifyDirectory(join(paths.projectRoot, 'src')), verifyDirectory(sourceIconDirectory), verifyRegularFile(sourceMacOsIconPath), verifyRegularFile(join(sourceIconDirectory, 'app-icon.ico')), verifyRegularFile(join(sourceIconDirectory, 'app-icon.png')), verifyRegularFile(packageMetadataPath), verifyRegularFile(join(paths.projectRoot, 'out', 'preload.cjs')), verifyRegularFile(sourceHelperPath), verifyRegularFile(sourceAddonPath), verifyRegularFile(sourceDaemonPlistPath), ...runtimeDependencies.map((dependency) => verifyDirectory(join(paths.projectRoot, 'node_modules', dependency)))])

    const packageMetadata = JSON.parse(await readFile(packageMetadataPath, 'utf8'))
    if (packageMetadata.name !== 'openrdxmanager' || packageMetadata.productName !== 'OpenRDXManager' || typeof packageMetadata.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(packageMetadata.version)) {
        throw new Error('macos-package-metadata-invalid')
    }

    await mkdir(paths.outputRoot, { recursive: true, mode: 0o700 })
    const temporaryAppPath = join(paths.outputRoot, `.OpenRDXManager-${randomUUID()}.app`)
    const temporaryContentsPath = join(temporaryAppPath, 'Contents')
    const temporaryResourcesPath = join(temporaryContentsPath, 'Resources')
    const execute = options.execFileImpl ?? execFileAsync
    try {
        await copyWithDitto(execute, sourceAppPath, temporaryAppPath)
        await rm(join(temporaryContentsPath, '_CodeSignature'), { force: true, recursive: true })
        await rm(join(temporaryResourcesPath, 'default_app.asar'), { force: true })
        await rename(join(temporaryContentsPath, 'MacOS', 'Electron'), join(temporaryContentsPath, 'MacOS', 'OpenRDXManager'))
        const plistPath = join(temporaryContentsPath, 'Info.plist')
        await setPlistString(execute, plistPath, 'CFBundleExecutable', 'OpenRDXManager')
        await setPlistString(execute, plistPath, 'CFBundleIdentifier', 'com.openrdx.manager')
        await setPlistString(execute, plistPath, 'CFBundleName', 'OpenRDXManager')
        await setPlistString(execute, plistPath, 'CFBundleDisplayName', 'OpenRDXManager')
        await setPlistString(execute, plistPath, 'CFBundleIconFile', 'OpenRDXManager.icns')
        await setPlistString(execute, plistPath, 'CFBundleShortVersionString', packageMetadata.version)
        await setPlistString(execute, plistPath, 'CFBundleVersion', packageMetadata.version)

        await copyWithDitto(execute, packageMetadataPath, join(temporaryResourcesPath, 'app', 'package.json'))
        await copyWithDitto(execute, join(paths.projectRoot, 'src'), join(temporaryResourcesPath, 'app', 'src'))
        await copyWithDitto(execute, sourceIconDirectory, join(temporaryResourcesPath, 'app', 'resources', 'icons'))
        await copyWithDitto(execute, sourceMacOsIconPath, join(temporaryResourcesPath, 'OpenRDXManager.icns'))
        await copyWithDitto(execute, join(paths.projectRoot, 'out', 'preload.cjs'), join(temporaryResourcesPath, 'app', 'out', 'preload.cjs'))
        for (const dependency of runtimeDependencies) {
            await copyWithDitto(execute, join(paths.projectRoot, 'node_modules', dependency), join(temporaryResourcesPath, 'app', 'node_modules', dependency))
        }
        const temporaryHelperPath = join(temporaryContentsPath, 'Library', 'LaunchServices', 'openrdx-hardware')
        const temporaryAddonPath = join(temporaryResourcesPath, 'native', 'macos', 'openrdx-service-management.node')
        await copyWithDitto(execute, sourceHelperPath, temporaryHelperPath)
        await copyWithDitto(execute, sourceAddonPath, temporaryAddonPath)
        await copyWithDitto(execute, sourceDaemonPlistPath, join(temporaryContentsPath, 'Library', 'LaunchDaemons', 'com.openrdx.hardware.plist'))
        await chmod(temporaryHelperPath, 0o755)

        const sign = (target, deep = false) => execute('/usr/bin/codesign', ['--force', ...(deep ? ['--deep'] : []), '--sign', options.signingIdentity, '--timestamp=none', target], { maxBuffer: 16 * 1024 * 1024 })
        await sign(temporaryHelperPath)
        await sign(temporaryAddonPath)
        await sign(temporaryAppPath, true)
        await execute('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', temporaryAppPath], { maxBuffer: 16 * 1024 * 1024 })

        await rm(paths.appPath, { force: true, recursive: true })
        await rename(temporaryAppPath, paths.appPath)
        return { appPath: paths.appPath }
    } finally {
        await rm(temporaryAppPath, { force: true, recursive: true })
    }
}

/** @param {string[]} arguments_ - CLI arguments after the script path. @returns {string} Explicit signing identity. */
function parseSigningIdentity(arguments_) {
    if (arguments_.length !== 2 || arguments_[0] !== '--signing-identity') throw new TypeError('macos-package-arguments-invalid')
    return arguments_[1]
}

/** @returns {Promise<void>} Runs one local package build from the command line. */
async function main() {
    const signingIdentity = parseSigningIdentity(process.argv.slice(2))
    const identity = await resolveMacOsSigningIdentity(signingIdentity)
    await execFileAsync(process.execPath, [join(defaultProjectRoot, 'scripts', 'build-preload.mjs')], { cwd: defaultProjectRoot, env: process.env, maxBuffer: 16 * 1024 * 1024 })
    await buildNativeService({ environment: { ...process.env, OPENRDX_MANAGER_TEAM_ID: identity.teamId }, platform: 'darwin', projectRoot: defaultProjectRoot })
    await buildMacOsServiceManagementAddon({ outputPath: join(defaultProjectRoot, 'out', 'native', 'macos', 'openrdx-service-management.node'), projectRoot: defaultProjectRoot })
    const outputRoot = join(defaultProjectRoot, 'dist', 'macos')
    const result = await packageMacOsApplication({ outputRoot, projectRoot: defaultProjectRoot, signingIdentity: identity.hash })
    process.stdout.write(`${result.appPath}\n`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    await main()
}
