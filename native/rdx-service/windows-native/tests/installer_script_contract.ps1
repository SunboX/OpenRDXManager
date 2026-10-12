# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
<# .SYNOPSIS Exercises the installer acceptance script's real Windows PowerShell native process boundary without installing anything. #>
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../../../../scripts/verify-windows-installation.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath).Path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'acceptance-script-syntax-error' }
foreach ($name in @('Invoke-CapturedProgram', 'Invoke-LocalAction', 'Assert-RemovedRuntime', 'Read-SetupDiagnostic', 'Invoke-Setup')) {
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
# The real setup process boundary preserves a denial's public diagnostics and
# still enforces a deadline when a program never exits. No installer is run here.
$runDirectory = Join-Path $env:TEMP ('openrdx-setup-capture-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDirectory | Out-Null
try {
    Invoke-Setup -Executable $env:ComSpec -Arguments '/d /c "echo setup-success & exit /b 0"'
    $rejected = $false
    try { Invoke-Setup -Executable $env:ComSpec -Arguments '/d /c "echo stage=prepare native-reason=AccessDenied 1>&2 & exit /b 3"' }
    catch { $rejected = $_.Exception.Message -match 'installer-failed: 3 diagnostics=.*stage=prepare native-reason=AccessDenied' }
    if (-not $rejected) { throw 'setup-native-denial-diagnostic-was-lost' }
    $rejected = $false
    try { Invoke-Setup -Executable $env:ComSpec -Arguments '/d /c "echo timeout-marker & ping -n 10 127.0.0.1 >nul"' -TimeoutMilliseconds 100 }
    catch { $rejected = $_.Exception.Message -match 'installer-timeout: diagnostics=.*timeout-marker' }
    if (-not $rejected) { throw 'setup-timeout-diagnostic-was-lost' }
    $large = Join-Path $runDirectory 'large-output'
    [IO.File]::WriteAllText($large, ('x' * 70000))
    $bounded = Read-SetupDiagnostic $large
    if ($bounded.Length -gt 65600 -or -not $bounded.EndsWith('[diagnostic-output-truncated]')) { throw 'setup-output-was-unbounded' }
} finally { Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction SilentlyContinue }
Write-Output 'Windows installer script native boundary passed'

# The complete custom script must initialize NSIS's readonly temp variable using
# the pinned compiler's supported instruction before helpers extract plugins.
$resources = Join-Path $PSScriptRoot '../../../../resources/installer'
foreach ($item in @(@('windows-installer.nsi', '.onInit'), @('windows-remover.nsi', '.onInit'))) {
    $text = Get-Content -LiteralPath (Join-Path $resources $item[0]) -Raw
    $pattern = 'Function ' + [regex]::Escape($item[1]) + '\s*\r?\n\s*;[^\n]*\n\s*UnsafeStrCpy \$TEMP "C:\\Program Files"'
    if ($text -notmatch $pattern) { throw 'protected-temp-must-precede-all-plugin-code' }
}
$uninstaller = Get-Content -LiteralPath (Join-Path $resources 'windows-remover.nsi') -Raw
$start = $uninstaller.IndexOf('Function .onInit')
$init = $uninstaller.Substring($start, $uninstaller.IndexOf('FunctionEnd', $start) - $start)
if ($init.IndexOf('!insertmacro OpenRDXPrepareRemoval') -lt 0 -or
    $init.IndexOf('!insertmacro OpenRDXPrepareRemoval') -gt $init.IndexOf('nsExec::ExecToStack')) {
    throw 'native-quiescence-must-precede-process-shutdown'
}
$files = Get-Content -LiteralPath (Join-Path $resources 'windows-install-files.nsh') -Raw
if ($files -match 'WriteUninstaller|\$\{UNINSTALLER_OUT_FILE\}' -or $uninstaller -match 'Section ["'']un\.|Function un\.') {
    throw 'remover-must-use-normal-nsis-entrypoint-without-self-copy'
}
Write-Output 'Windows pinned template lifecycle contract passed'

# Exercise the real residue guard against protected disposable filesystem objects.
$fixture = Join-Path $env:TEMP ('openrdx-removal-residue-' + [Guid]::NewGuid().ToString('N'))
$self = Join-Path $fixture 'Uninstall OpenRDXManager.exe'
try {
    Assert-RemovedRuntime -RuntimeRoot $fixture
    New-Item -ItemType Directory -Path $fixture | Out-Null
    Set-Content -LiteralPath $self -Value 'disposable-remover'
    $directoryAcl = New-Object Security.AccessControl.DirectorySecurity
    $directoryAcl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;LS)(A;OICI;FRFX;;;BU)')
    Set-Acl -LiteralPath $fixture -AclObject $directoryAcl
    $fileAcl = New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;LS)(A;;FRFX;;;BU)')
    Set-Acl -LiteralPath $self -AclObject $fileAcl
    Assert-RemovedRuntime -RuntimeRoot $fixture -PendingDeletes @("\??\$self", '')
    Assert-RemovedRuntime -RuntimeRoot $fixture -PendingDeletes @("*1\??\$self", '')
    foreach ($pending in @(@(), @("\??\$self", '\??\C:\wrong-destination'), @('\??\C:\other-file', ''))) {
        $rejected = $false
        try { Assert-RemovedRuntime -RuntimeRoot $fixture -PendingDeletes $pending }
        catch { $rejected = $_.Exception.Message -eq 'pending-own-remover-delete-unconfirmed' }
        if (-not $rejected) { throw 'unscheduled-or-renamed-remover-was-accepted' }
    }
    Set-Content -LiteralPath (Join-Path $fixture 'unexpected-payload') -Value 'disposable-residue'
    $rejected = $false
    try { Assert-RemovedRuntime -RuntimeRoot $fixture -PendingDeletes @("\??\$self", '') }
    catch { $rejected = $_.Exception.Message -eq 'unexpected-runtime-removal-residue' }
    if (-not $rejected) { throw 'unexpected-removal-residue-was-accepted' }
    Remove-Item -LiteralPath (Join-Path $fixture 'unexpected-payload')
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;LS)(A;;FA;;;BU)')
    Set-Acl -LiteralPath $self -AclObject $fileAcl
    $rejected = $false
    try { Assert-RemovedRuntime -RuntimeRoot $fixture -PendingDeletes @("\??\$self", '') }
    catch { $rejected = $_.Exception.Message -eq 'noncanonical-runtime-removal-residue' }
    if (-not $rejected) { throw 'unprivileged-mutable-remover-residue-was-accepted' }
} finally { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
Write-Output 'Windows strict removal residue contract passed'
