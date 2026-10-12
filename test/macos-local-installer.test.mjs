// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const execute = promisify(execFile)

test('both macOS socket registrations give the authenticated console user staff access', async () => {
    for (const relative of ['resources/installer/macos/com.openrdx.hardware.plist', 'native/rdx-service/resources/macos/com.openrdx.hardware.plist']) {
        const source = await readFile(new URL(`../${relative}`, import.meta.url), 'utf8')
        assert.match(source, /<key>SockPathOwner<\/key>\s*<integer>0<\/integer>/u)
        assert.match(source, /<key>SockPathGroup<\/key>\s*<integer>20<\/integer>/u)
    }
})

/**
 * Resolve one checked-in package script without depending on the working directory.
 * @param {string} name Checked-in script basename.
 * @returns {string} Absolute package script path.
 */
function scriptPath(name) {
    return fileURLToPath(new URL(`../resources/installer/macos/${name}`, import.meta.url))
}

for (const name of ['preinstall', 'postinstall']) {
    test(`macOS ${name} rejects another volume before any elevated native action`, async () => {
        await assert.rejects(execute('/bin/sh', [scriptPath(name), 'package.pkg', '/Applications', '/Volumes/Untrusted']), (error) => error.code === 1 && /running startup volume/.test(error.stderr))
    })
}

test('macOS uninstall refuses caller-selected service/path arguments', async () => {
    await assert.rejects(execute('/bin/sh', [scriptPath('uninstall.sh'), '/tmp/foreign.app']), (error) => error.code === 1 && /accepts no path or service arguments/.test(error.stderr))
})

for (const name of ['preinstall', 'postinstall', 'uninstall.sh']) {
    test(`macOS ${name} parses with its fixed shell interpreter`, async () => {
        await execute('/bin/sh', ['-n', scriptPath(name)])
    })
}
