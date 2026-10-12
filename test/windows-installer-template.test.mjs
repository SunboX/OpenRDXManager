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
    const uninstaller = await source('windows-remover.nsi')
    for (const [text, name] of [
        [installer, '.onInit'],
        [uninstaller, '.onInit']
    ]) {
        assert.match(text, new RegExp(`Function ${name.replaceAll('.', '\\.')}\\s*\\n\\s*;[^\\n]*\\n\\s*UnsafeStrCpy \\$TEMP "C:\\\\Program Files"`))
        assert.ok(text.split('\n').length < 1000)
    }
    assert.doesNotMatch(installer, /BUILD_UNINSTALLER|MUI_UNPAGE|windows-uninstaller/u)
    assert.doesNotMatch(uninstaller, /Section ["']un\.|Function un\.|WriteUninstaller/u)
    assert.match(uninstaller, /RequestExecutionLevel admin/u)
    assert.match(installer, /RequestExecutionLevel admin/)
    const files = await source('windows-install-files.nsh')
    assert.doesNotMatch(files, /WriteUninstaller/u)
    assert.doesNotMatch(files, /\$\{UNINSTALLER_OUT_FILE\}/)
    assert.match(installer, /OpenRDX requires one architecture per installer/)
})

test('normal remover proves native ownership before process checks and preserves personal data', async () => {
    const text = await source('windows-remover.nsi')
    const initialization = text.slice(text.indexOf('Function .onInit'), text.indexOf('FunctionEnd', text.indexOf('Function .onInit')))
    assert.ok(initialization.indexOf('!insertmacro OpenRDXPrepareRemoval') < initialization.indexOf('nsExec::ExecToStack'))
    assert.match(initialization, /!insertmacro OpenRDXPrepareRemoval/)
    const hook = await source('windows-service.nsh')
    assert.match(hook, /!macro OpenRDXPrepareRemoval[\s\S]*--action prepare/)
    const removal = hook.slice(hook.indexOf('!macro customUnInstall'))
    assert.doesNotMatch(removal, /--action prepare/)
    assert.match(removal, /--action remove/)
    assert.match(text, /RMDir \/r \/REBOOTOK "\$\{OPENRDX_FIXED_ROOT\}"/u)
    assert.doesNotMatch(text, /RMDir[^\n]*\$(?:APPDATA|LOCALAPPDATA)/u)
})
