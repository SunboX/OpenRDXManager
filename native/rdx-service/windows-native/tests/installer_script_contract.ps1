# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
<# .SYNOPSIS Exercises the installer acceptance script's real Windows PowerShell native process boundary without installing anything. #>
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../../../../scripts/verify-windows-installation.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath).Path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'acceptance-script-syntax-error' }
foreach ($name in @('Invoke-CapturedProgram', 'Invoke-LocalAction')) {
    $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if (-not $function) { throw "acceptance-script-function-missing: $name" }
    Invoke-Expression $function.Extent.Text
}
$result = Invoke-CapturedProgram -Executable $env:ComSpec -Arguments @('/d', '/c', 'echo test-stdout & echo test-stderr 1>&2 & exit /b 3')
if ($result.exitCode -ne 3 -or $result.output -notmatch 'test-stdout' -or $result.output -notmatch 'test-stderr' -or $ErrorActionPreference -ne 'Stop') {
    throw 'expected-native-denial-capture-failed'
}
# The exact source function must forward one complete named array, including its
# native command arguments, and reject a failing process after capturing stderr.
$provisioner = $env:ComSpec
Invoke-LocalAction -Arguments @('/d', '/c', 'echo named-array-forwarded & exit /b 0')
$rejected = $false
try { Invoke-LocalAction -Arguments @('/d', '/c', 'echo expected-native-denial 1>&2 & exit /b 3') }
catch { $rejected = $_.Exception.Message -match 'native-action-failed: /c code=3' }
if (-not $rejected) { throw 'failing-native-action-was-accepted' }
Write-Output 'Windows installer script native boundary passed'

# The complete custom script must initialize NSIS's readonly temp variable using
# the pinned compiler's supported instruction before helpers extract plugins.
$resources = Join-Path $PSScriptRoot '../../../../resources/installer'
foreach ($item in @(@('windows-installer.nsi', '.onInit'), @('windows-uninstaller.nsh', 'un.onInit'))) {
    $text = Get-Content -LiteralPath (Join-Path $resources $item[0]) -Raw
    $pattern = 'Function ' + [regex]::Escape($item[1]) + '\s*\r?\n\s*;[^\n]*\n\s*UnsafeStrCpy \$TEMP "\$WINDIR\\Temp"'
    if ($text -notmatch $pattern) { throw 'protected-temp-must-precede-all-plugin-code' }
}
$uninstaller = Get-Content -LiteralPath (Join-Path $resources 'windows-uninstaller.nsh') -Raw
$start = $uninstaller.IndexOf('Function un.onInit')
$init = $uninstaller.Substring($start, $uninstaller.IndexOf('FunctionEnd', $start) - $start)
if ($init.IndexOf('!insertmacro OpenRDXPrepareRemoval') -lt 0 -or
    $init.IndexOf('!insertmacro OpenRDXPrepareRemoval') -gt $init.IndexOf('call un.checkAppRunning')) {
    throw 'native-quiescence-must-precede-process-shutdown'
}
$files = Get-Content -LiteralPath (Join-Path $resources 'windows-install-files.nsh') -Raw
if ($files -notmatch 'WriteUninstaller "\$INSTDIR\\\$\{UNINSTALL_FILENAME\}"' -or $files -match '\$\{UNINSTALLER_OUT_FILE\}') {
    throw 'custom-script-must-generate-its-own-uninstaller'
}
Write-Output 'Windows pinned template lifecycle contract passed'
