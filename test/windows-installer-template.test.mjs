// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** Reads a maintained installer source relative to this test. @param {string} name Source name. @returns {Promise<string>} Source text. */
async function source(name) {
    return readFile(new URL(`../resources/installer/${name}`, import.meta.url), 'utf8')
}

test('pinned templates choose protected temp before any installer or uninstaller work', async () => {
    const installer = await source('windows-installer.nsi')
    const uninstaller = await source('windows-uninstaller.nsh')
    for (const [text, name] of [
        [installer, '.onInit'],
        [uninstaller, 'un.onInit']
    ]) {
        assert.match(text, new RegExp(`Function ${name.replaceAll('.', '\\.')}\\s*\\n\\s*;[^\\n]*\\n\\s*UnsafeStrCpy \\$TEMP "\\$WINDIR\\\\Temp"`))
        assert.ok(text.split('\n').length < 1000)
        assert.match(text, /Copyright \(c\) 2015 Loopline Systems/)
    }
    assert.match(installer, /!include "\$\{BUILD_RESOURCES_DIR\}\\windows-uninstaller\.nsh"/)
    assert.match(installer, /RequestExecutionLevel admin/)
    const files = await source('windows-install-files.nsh')
    assert.match(files, /WriteUninstaller "\$INSTDIR\\\$\{UNINSTALL_FILENAME\}"/)
    assert.doesNotMatch(files, /\$\{UNINSTALLER_OUT_FILE\}/)
    assert.match(installer, /OpenRDX requires one architecture per installer/)
})

test('uninstaller quiesces native ownership before process shutdown checks', async () => {
    const text = await source('windows-uninstaller.nsh')
    const initialization = text.slice(text.indexOf('Function un.onInit'), text.indexOf('FunctionEnd', text.indexOf('Function un.onInit')))
    assert.ok(initialization.indexOf('!insertmacro OpenRDXPrepareRemoval') < initialization.indexOf('call un.checkAppRunning'))
    assert.match(initialization, /!insertmacro OpenRDXPrepareRemoval/)
    const hook = await source('windows-service.nsh')
    assert.match(hook, /!macro OpenRDXPrepareRemoval[\s\S]*--action prepare/)
    const removal = hook.slice(hook.indexOf('!macro customUnInstall'))
    assert.doesNotMatch(removal, /--action prepare/)
    assert.match(removal, /--action remove/)
})
