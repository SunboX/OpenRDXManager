// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** Reads a maintained installer source relative to this test. @param {string} name Source name. @returns {Promise<string>} Source text. */
async function source(name) {
    return readFile(new URL(`../resources/installer/${name}`, import.meta.url), 'utf8')
}

test('Windows setup completion explains the reconnect needed to activate device permissions', async () => {
    const installer = await source('windows-installer.nsi')
    assert.match(installer, /!define MUI_FINISHPAGE_TEXT "[^\n]*Reconnect the RDX dock's USB cable[^\n]*Retry service and Scan/u)
    assert.ok(installer.indexOf('!define MUI_FINISHPAGE_TEXT') < installer.indexOf('!include "assistedInstaller.nsh"'))
})

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

test('assisted setup retains closed diagnostics after a dismissed failure dialog', async () => {
    const installer = await source('windows-installer.nsi')
    const common = await readFile(new URL('../node_modules/app-builder-lib/templates/nsis/common.nsh', import.meta.url), 'utf8')
    // The upstream template disables the details view. Our later declaration
    // must override that default so an aborted page retains an inspectable log.
    const declarations = `${common}\n${installer.slice(installer.indexOf('!include "common.nsh"') + '!include "common.nsh"'.length)}`.match(/^ShowInstDetails\s+\w+/gmu)
    assert.equal(declarations?.at(-1), 'ShowInstDetails show')
    const hook = await source('windows-service.nsh')
    const diagnosticStart = hook.indexOf('!macro OpenRDXWriteDiagnostic MESSAGE')
    const diagnostic = hook.slice(diagnosticStart, hook.indexOf('!macroend', diagnosticStart))
    // The install section turns printing off; only the closed diagnostic gets
    // a temporary list mode, then the caller's original mode is restored.
    assert.match(diagnostic, /SetDetailsPrint listonly\s*\n\s*DetailPrint "\$R7"\s*\n\s*SetDetailsPrint lastused/u)
    const failureStart = hook.indexOf('!macro OpenRDXFail STAGE CODE MESSAGE')
    const failure = hook.slice(failureStart, hook.indexOf('!macroend', failureStart))
    assert.match(failure, /\$\{IfNot\} \$\{Silent\}\s*\n\s*SetDetailsView show\s*\n\s*MessageBox/u)
    assert.match(failure, /SetErrorLevel 3\s*\n\s*Abort/u)
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
    for (const phase of ['runtime', 'process', 'user', 'configuration', 'dacl', 'registry', 'revalidation', 'user-elevation', 'user-elevation-size', 'user-session', 'user-principal', 'user-query']) {
        const token = `manager-${phase}`
        assert.ok(native.includes(`=> "${token}"`), token)
        assert.ok(hook.includes(`"phase=${token} reason="`), token)
        assert.ok(hook.indexOf(`"phase=${token} reason="`) > hook.indexOf('"phase=manager-access reason="'))
    }
})

test('Manager elevation size and elevated value keep separate fail-closed native denials', async () => {
    const token = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/manager_token.rs', import.meta.url), 'utf8')
    assert.match(token, /if returned_elevation as usize != size_of::<windows::Win32::Security::TOKEN_ELEVATION>\(\)\s*\{\s*return diagnostic\(\s*Stage::ManagerUserElevationSize,\s*Err\(NativeError::AccessDenied\),?\s*\);/u)
    assert.match(token, /if elevation\.TokenIsElevated != 0\s*\{\s*return diagnostic\(Stage::ManagerUserElevation, Err\(NativeError::AccessDenied\)\);/u)
})

test('StdUtils launch diagnostics reconstruct closed result tokens without forwarding arbitrary plugin output', async () => {
    const hook = await source('windows-service.nsh')
    const start = hook.indexOf('!macro OpenRDXSanitizeLaunchResult')
    assert.ok(start >= 0)
    const sanitizer = hook.slice(start, hook.indexOf('!macroend', start))
    for (const result of ['ok', 'fallback', 'unsupported', 'error', 'einval', 'timeout', 'not_found', 'unknown']) assert.ok(sanitizer.includes(`"${result}"`), result)
    assert.doesNotMatch(sanitizer, /StrCpy \$\{OUTPUT\} "?\$\{INPUT\}/u)
    assert.match(hook, /ExecShellAsUser[^\n]*\n\s*!insertmacro OpenRDXSanitizeLaunchResult "\$0" \$R4\s*\n\s*!insertmacro OpenRDXWriteDiagnostic "OpenRDX Manager launch: result=\$R4"/u)
})

test('Windows installation retains the private backup store before admission and publishes closed storage errors', async () => {
    const native = await readFile(new URL('../native/rdx-service/windows-native/src/installer/windows.rs', import.meta.url), 'utf8')
    const phases = await readFile(new URL('../native/rdx-service/windows-native/src/installer/diagnostics.rs', import.meta.url), 'utf8')
    const hook = await source('windows-service.nsh')
    const install = native.slice(native.indexOf('let result = (|| {'), native.indexOf('if let Err(error) = result'))
    const store = install.indexOf('let _manufacturing_store =')
    assert.ok(store > install.indexOf('prepare_runtime(&administrator_sid)'))
    assert.ok(store < install.indexOf('for action in ["provision", "verify"]'))
    assert.match(install, /let _manufacturing_store = diagnostic\(\s*Stage::ManufacturingStorage,\s*crate::manufacturing_storage::ManufacturingStore::open\(\),\s*\)\?;/u)
    assert.ok(install.indexOf('commit_enrollment(') > store)
    assert.ok(phases.includes('=> "manufacturing-storage"'))
    assert.ok(hook.includes('"phase=manufacturing-storage reason="'))
})

test('installer media deferral brackets the query and journals repairs before permission writes', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/native/device_access.rs', import.meta.url), 'utf8')
    const readyStart = source.indexOf('fn mapped_volumes_for_device(')
    assert.ok(readyStart >= 0)
    const ready = source.slice(readyStart, source.indexOf('///', readyStart + 1))
    assert.ok(ready.indexOf('device.revalidate_exact()?') < ready.indexOf('DeviceIoControl('))
    assert.ok(ready.lastIndexOf('device.revalidate_exact()?') > ready.indexOf('DeviceIoControl('))
    assert.ok(ready.indexOf('volume_media_ready(') > ready.lastIndexOf('device.revalidate_exact()?'))
    const enrollment = source.slice(source.indexOf('pub(crate) fn provision('), source.indexOf('pub(crate) fn restore('))
    const deviceStart = enrollment.indexOf('for candidate in enumerate_disk_candidates()?')
    assert.ok(deviceStart >= 0)
    const privilege = enrollment.slice(0, deviceStart)
    assert.match(privilege, /journal::enroll\(&mut VolumeRightJournal\(&mut records\)\)\?;/u)
    const provision = enrollment.slice(deviceStart)
    assert.ok(provision.indexOf('rdx_identity(') < provision.indexOf('mapped_volumes_for_device('))
    assert.ok(provision.indexOf('plan_volume_policies(') < provision.indexOf('write_records('))
    assert.ok(provision.indexOf('write_records(') < provision.indexOf('set_instance_policy('))
    const restore = source.slice(source.indexOf('pub(crate) fn restore('), source.indexOf('fn volume_info_set('))
    assert.match(restore, /mapped_volumes_for_device\(/u)
    assert.match(restore, /if !crate::safe_device_acl_repair\(/u)
    assert.match(source, /open_path\(&path, READ_CONTROL\.0\)/u)
    const mapping = source.slice(source.indexOf('fn mapped_volumes('), source.indexOf('fn topology_key('))
    assert.ok(mapping.indexOf('open_path(&path, 0)') < mapping.indexOf('classify_volume_probe('))
    assert.ok(mapping.indexOf('classify_volume_probe(') < mapping.indexOf('open_path(&path, READ_CONTROL.0)'))
})
