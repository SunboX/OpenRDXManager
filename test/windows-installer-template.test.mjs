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

test('native installer denials emit a stage and terminate silent setup with failure', async () => {
    const hook = await source('windows-service.nsh')
    assert.match(hook, /!macro OpenRDXFail STAGE CODE MESSAGE/u)
    assert.match(hook, /GetStdHandle\(i -12\)/u)
    assert.match(hook, /WriteFile/u)
    assert.match(hook, /SetErrorLevel 3\s*\n\s*Abort/u)
    assert.match(hook, /\$\{IfNot\} \$\{Silent\}[\s\S]*MessageBox[\s\S]*\$\{EndIf\}/u)
    for (const stage of ['manager-process']) {
        assert.ok(hook.includes('!insertmacro OpenRDXFail "' + stage + '"'))
    }
    for (const stage of ['prepare', 'install', 'verify', 'removal-prepare', 'remove']) {
        assert.ok(hook.includes('!insertmacro OpenRDXNativeFail "' + stage + '"'))
    }
    const nativeFailure = hook.slice(hook.indexOf('!macro OpenRDXNativeFail'), hook.indexOf('!macroend', hook.indexOf('!macro OpenRDXNativeFail')))
    assert.doesNotMatch(nativeFailure, /OpenRDXFail[^\n]*\$1/u)
    const remover = await source('windows-remover.nsi')
    assert.doesNotMatch(remover, /MessageBox/u)
    assert.match(remover, /!insertmacro OpenRDXFail "removal-files"/u)
})

test('NSIS Manager queries keep exact process predicates inside one Windows command argument', async () => {
    for (const name of ['windows-service.nsh', 'windows-remover.nsi']) {
        const text = await source(name)
        const query = text.split('\n').find((line) => line.includes('Get-CimInstance Win32_Process'))
        assert.ok(query, name)
        // NSIS's escaped quote becomes an unescaped Windows argument quote.
        // PowerShell then strips WQL string quotes and rejects the query.
        assert.doesNotMatch(query, /\$\\"/u)
        assert.match(query, /\$\$_\.Name -eq 'OpenRDXManager\.exe'/u)
        assert.match(query, /\$\$_\.ExecutablePath -eq '\$\{OPENRDX_FIXED_ROOT\}\\OpenRDXManager\.exe'/u)
    }
})

test('installed runtime diagnostics remain closed and select the specific native boundary', async () => {
    const native = await readFile(new URL('../native/rdx-service/windows-native/src/installer/diagnostics.rs', import.meta.url), 'utf8')
    const hook = await source('windows-service.nsh')
    for (const phase of ['ancestors', 'open', 'protection', 'pinning', 'manifest', 'inventory', 'artifacts', 'history']) {
        const token = `runtime-${phase}`
        assert.ok(native.includes(`=> "${token}"`), token)
        assert.ok(hook.includes(`"phase=${token} reason="`), token)
        assert.ok(hook.indexOf(`"phase=${token} reason="`) > hook.indexOf('"phase=installed-runtime reason="'))
    }
})

test('manager diagnostics preserve closed specific phases after their enclosing denial', async () => {
    const native = await readFile(new URL('../native/rdx-service/windows-native/src/installer/diagnostics.rs', import.meta.url), 'utf8')
    const hook = await source('windows-service.nsh')
    for (const phase of ['runtime', 'process', 'user', 'configuration', 'dacl', 'registry', 'revalidation', 'user-elevation', 'user-session', 'user-principal', 'user-query']) {
        const token = `manager-${phase}`
        assert.ok(native.includes(`=> "${token}"`), token)
        assert.ok(hook.includes(`"phase=${token} reason="`), token)
        assert.ok(hook.indexOf(`"phase=${token} reason="`) > hook.indexOf('"phase=manager-access reason="'))
    }
})
