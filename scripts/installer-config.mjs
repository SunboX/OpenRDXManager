// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** @param {{arch: number}} context - Electron-builder target architecture enum. @returns {void} Rejects mixing native host helpers with a different Electron architecture. */
function verifyNativeArchitecture(context) {
    const expected = { x64: 1, arm64: 3 }[process.arch]
    if (expected === undefined || context.arch !== expected) throw new Error('native-installer-architecture-mismatch')
}

/**
 * Builds installers with only application-owned files and the native host runtime.
 * Native helpers stay outside ASAR at the main process's existing fixed paths.
 * @param {'darwin'|'win32'|'linux'} platform - Native packaging host.
 * @returns {object} Electron-builder configuration, with manifest-owned version.
 * @throws {RangeError} For unsupported build hosts.
 */
export function createInstallerConfiguration(platform) {
    const folder = { darwin: 'macos', win32: 'windows', linux: 'linux' }[platform]
    if (!folder) throw new RangeError('unsupported-installer-platform')
    return {
        appId: 'com.openrdx.manager',
        productName: 'OpenRDXManager',
        executableName: 'OpenRDXManager',
        // Linux target macros otherwise rename x64 to amd64/x86_64. The native
        // host architecture keeps all fourteen release filenames consistent.
        artifactName: `OpenRDXManager-\${version}-\${os}-${process.arch}.\${ext}`,
        directories: { output: 'dist/installers', buildResources: 'resources/installer' },
        asar: true,
        // Copied MCP configurations invoke external Node, which cannot read ASAR.
        // Keep the bridge's ordinary ESM/package/dependency tree together.
        asarUnpack: ['scripts/mcp-stdio.mjs', 'src/main/**/*', 'package.json', 'node_modules/**/*'],
        npmRebuild: false,
        beforePack: verifyNativeArchitecture,
        files: ['package.json', 'src/**/*', 'scripts/mcp-stdio.mjs', 'out/preload.cjs', 'resources/icons/**/*', 'LICENSE', 'LICENSES/**/*', 'NOTICE', 'COMMERCIAL-LICENSE.md'],
        extraResources: [
            { from: `out/native/${folder}`, to: `native/${folder}` },
            { from: `native/rdx-service/resources/${folder}`, to: `native/${folder}`, filter: ['**/*', '!README.md'] }
        ],
        mac: {
            category: 'public.app-category.utilities',
            icon: 'resources/icons/app-icon.icns',
            identity: '-',
            hardenedRuntime: false,
            notarize: false,
            minimumSystemVersion: '13.0',
            target: ['dmg', 'zip'],
            extraFiles: [
                { from: 'out/native/macos/openrdx-hardware', to: 'Library/LaunchServices/openrdx-hardware' },
                { from: 'native/rdx-service/resources/macos/com.openrdx.hardware.plist', to: 'Library/LaunchDaemons/com.openrdx.hardware.plist' }
            ]
        },
        win: { icon: 'resources/icons/app-icon.ico', target: ['nsis', 'zip'], signAndEditExecutable: true },
        nsis: { oneClick: false, perMachine: true, allowToChangeInstallationDirectory: true, runAfterFinish: false, deleteAppDataOnUninstall: false },
        linux: {
            category: 'Utility',
            icon: 'resources/icons/app-icon.png',
            maintainer: 'André Fiedler <83344+SunboX@users.noreply.github.com>',
            target: ['AppImage', 'deb', 'tar.gz']
        },
        deb: {
            depends: ['libgtk-3-0', 'libnss3', 'libxss1', 'libxtst6', 'libatspi2.0-0', 'libsecret-1-0', 'libgbm1', 'udisks2', 'policykit-1', 'systemd'],
            afterInstall: 'resources/installer/linux-after-install.sh',
            afterRemove: 'resources/installer/linux-after-remove.sh'
        },
        publish: null
    }
}

export default createInstallerConfiguration(process.platform)
