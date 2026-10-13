# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
<# .SYNOPSIS Exercises the installer acceptance script's real Windows PowerShell native process boundary without installing anything. #>
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../../../../scripts/verify-windows-installation.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath).Path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'acceptance-script-syntax-error' }
foreach ($name in @('Invoke-CapturedProgram', 'Invoke-LocalAction', 'Assert-RemovedRuntime', 'Read-SetupDiagnostic', 'Invoke-Setup', 'Get-TokenDiagnostic', 'Write-ManagerWorkerDiagnostic', 'Invoke-ManagerSetup', 'Wait-Worker')) {
    $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if (-not $function) { throw "acceptance-script-function-missing: $name" }
    Invoke-Expression $function.Extent.Text
}
# Compile the production read-only token queries; no installer or worker is launched.
$typeCommand = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type' }, $true)
Invoke-Expression $typeCommand.Extent.Text
$ownFacts = Get-TokenDiagnostic -ProcessId $PID
if (-not $ownFacts.ElevationQueryOk -or -not $ownFacts.ElevationSizeMatch -or -not $ownFacts.SessionQueryOk -or -not $ownFacts.SessionSizeMatch -or -not $ownFacts.TokenMatchesProcessSession) { throw 'read-only-self-token-query-failed' }
<# .SYNOPSIS Extracts one production NSIS macro, preserving its exact instructions. .PARAMETER Name Closed fixture macro name. #>
function Get-DiagnosticMacro([string]$Name) {
    $hook = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../../../../resources/installer/windows-service.nsh')
    $match = [regex]::Match($hook, '(?ms)^!macro ' + [regex]::Escape($Name) + '[^\n]*\n.*?^!macroend')
    if (-not $match.Success) { throw 'diagnostic-macro-missing' }
    return $match.Value
}
<# .SYNOPSIS Compiles and executes a test-only parser, never a production installer or launch operation. .PARAMETER Compiler Checksum-pinned NSIS compiler. .PARAMETER Macro Exact production parser/sanitizer. .PARAMETER Body Closed fixture instructions. #>
function Invoke-DiagnosticParserFixture([string]$Compiler, [string]$Macro, [string]$Body) {
    $name = [Guid]::NewGuid().ToString('N')
    $report = Join-Path $runDirectory "$name.report"
    $executable = Join-Path $runDirectory "$name.exe"
    $script = Join-Path $runDirectory "$name.nsi"
    $template = @'
Unicode true
RequestExecutionLevel admin
SilentInstall silent
Name "OpenRDX disposable diagnostic parser"
OutFile "__EXE__"
!include "LogicLib.nsh"
!include "StrFunc.nsh"
${StrStr}
!macro OpenRDXFail STAGE CODE MESSAGE
  FileOpen $9 "__REPORT__" w
  FileWrite $9 "stage=${STAGE} code=${CODE} ${MESSAGE}$\r$\n"
  FileClose $9
  SetErrorLevel 3
  Quit
!macroend
__MACRO__
Section
__BODY__
SectionEnd
'@
    $text = $template.Replace('__EXE__', $executable).Replace('__REPORT__', $report).Replace('__MACRO__', $Macro).Replace('__BODY__', $Body.Replace('__REPORT__', $report))
    [IO.File]::WriteAllText($script, $text, (New-Object Text.UTF8Encoding($true)))
    $compiled = Invoke-CapturedProgram -Executable $Compiler -Arguments @('/V2', $script)
    if ($compiled.exitCode -ne 0) { throw "diagnostic-fixture-compile-failed: $($compiled.output)" }
    $process = Start-Process -FilePath $executable -ArgumentList '/S' -PassThru
    try {
        $handle = $process.Handle
        if (-not $process.WaitForExit(10000)) { throw 'diagnostic-fixture-timeout' }
        return @{ code=$process.ExitCode; report=(Read-SetupDiagnostic $report); executable=$executable }
    } finally { if (-not $process.HasExited) { $process.Kill(); $null=$process.WaitForExit(5000) }; $process.Dispose() }
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
    # The deadline includes process startup: no output is required before it.
    # Native-denial capture above separately proves emitted diagnostics survive.
    # Use one process so termination leaves no ping/sleep child behind.
    $sleeper = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    try { Invoke-Setup -Executable $sleeper -Arguments '-NoProfile -NonInteractive -Command "[Console]::WriteLine(''timeout-marker''); Start-Sleep -Seconds 10"' -TimeoutMilliseconds 100 }
    catch { $rejected = $_.Exception.Message -match '^installer-timeout: diagnostics=' }
    if (-not $rejected) { throw 'setup-deadline-was-not-enforced' }
    $large = Join-Path $runDirectory 'large-output'
    [IO.File]::WriteAllText($large, ('x' * 70000))
    $bounded = Read-SetupDiagnostic $large
    if ($bounded.Length -gt 65600 -or -not $bounded.EndsWith('[diagnostic-output-truncated]')) { throw 'setup-output-was-unbounded' }
    $resultPath = Join-Path $runDirectory 'worker-result.json'
    $fake = @{ ok=$false; error='raw-secret-error'; pid=424242; workerDiagnostic=@{prerequisite='console-mismatch';facts=$ownFacts}; managerDiagnostic=$ownFacts }
    $fake | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $diagnostic = Write-ManagerWorkerDiagnostic -Path $resultPath | Out-String
    if ($diagnostic -notmatch 'prerequisite=console-mismatch' -or $diagnostic -notmatch 'OpenRDX worker-selected Manager: elevation-query=True elevation-size-match=True' -or
        $diagnostic -match 'raw-secret-error|424242' -or $diagnostic.Length -gt 1024) { throw 'worker-diagnostic-not-closed' }
    $fake.workerDiagnostic.prerequisite = 'raw-secret-stage'
    $fake | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $diagnostic = Write-ManagerWorkerDiagnostic -Path $resultPath | Out-String
    if ($diagnostic -notmatch 'prerequisite=unknown' -or $diagnostic -match 'raw-secret-stage') { throw 'worker-stage-not-sanitized' }
    [IO.File]::WriteAllText($resultPath, ('x' * 70000))
    if ((Write-ManagerWorkerDiagnostic -Path $resultPath | Out-String) -notmatch 'result=unbounded') { throw 'worker-output-not-bounded' }
    [IO.File]::WriteAllText($resultPath, 'invalid-raw-secret-json')
    if ((Write-ManagerWorkerDiagnostic -Path $resultPath | Out-String) -notmatch 'result=unavailable') { throw 'worker-parse-error-not-sanitized' }
    Remove-Item -LiteralPath $resultPath
    if ((Write-ManagerWorkerDiagnostic -Path $resultPath | Out-String) -notmatch 'result=not-observed') { throw 'missing-worker-result-not-diagnosed' }
    # Resolve the same pinned compiler used by production. These executables only
    # record parser output: no plugins, launch operations, service or device APIs.
    $compilerPath = Join-Path $runDirectory 'compiler-path'
    Push-Location (Join-Path $PSScriptRoot '../../../..')
    try {
        # Downloads can log to stdout; keep the resolved path in an exact owned file.
        & node --input-type=module -e "import {getMakeNsisPath} from 'app-builder-lib/out/toolsets/windows.js'; import {writeFile} from 'node:fs/promises'; await writeFile(process.argv[1],await getMakeNsisPath('1.2.1'),'utf8')" $compilerPath
        $compilerExit = $LASTEXITCODE
    }
    finally { Pop-Location }
    if ($compilerExit -ne 0 -or -not (Test-Path -LiteralPath $compilerPath)) { throw 'pinned-fixture-compiler-unavailable' }
    $compiler = [IO.File]::ReadAllText($compilerPath)
    if (-not (Test-Path -LiteralPath $compiler)) { throw 'pinned-fixture-compiler-unavailable' }
    $nativeParser = Get-DiagnosticMacro 'OpenRDXNativeFail'
    $sizeBlock = [regex]::Match($nativeParser, '(?ms)^  \$\{StrStr\} \$R5 "\$1" "phase=manager-user-elevation-size reason=".*?^  \$\{EndIf\}').Value
    if (-not $sizeBlock) { throw 'specific-elevation-size-parser-missing' }
    foreach ($phase in @('manager-user-elevation-size', 'manager-user-elevation')) {
        $body = '  StrCpy $0 3' + "`n" + '  StrCpy $1 "phase=' + $phase + ' reason=AccessDenied$\r$\nphase=manager-user reason=AccessDenied$\r$\nphase=entrypoint reason=AccessDenied raw=S-1-5-21-123 path=C:\private-fixture"' + "`n" + '  !insertmacro OpenRDXNativeFail "fixture" "closed"'
        $final = Invoke-DiagnosticParserFixture -Compiler $compiler -Macro $nativeParser -Body $body
        if ($final.code -ne 3 -or $final.report -cne "stage=fixture code=3 closed native-phase=$phase native-reason=AccessDenied`r`n") { throw 'specific-native-parser-output-failed' }
        $denialFixture = $final
        if ($phase -eq 'manager-user-elevation-size') {
            $baseline = Invoke-DiagnosticParserFixture -Compiler $compiler -Macro ($nativeParser.Replace($sizeBlock, '')) -Body $body
            if ($baseline.code -ne 3 -or $baseline.report -notmatch 'native-phase=manager-user native-reason=AccessDenied') { throw 'parser-baseline-mutation-not-reproduced' }
        }
    }
    $sanitizer = Get-DiagnosticMacro 'OpenRDXSanitizeLaunchResult'
    foreach ($pluginResult in @('ok', 'fallback', 'unsupported', 'error', 'einval', 'timeout', 'not_found', 'unknown', 'raw-S-1-5-21-123-path-C:\private-fixture')) {
        $body = '  !insertmacro OpenRDXSanitizeLaunchResult "' + $pluginResult + '" $R4' + "`n" + '  FileOpen $9 "__REPORT__" w' + "`n" + '  FileWrite $9 "$R4"' + "`n" + '  FileClose $9' + "`n" + '  SetErrorLevel 0' + "`n" + '  Quit'
        $final = Invoke-DiagnosticParserFixture -Compiler $compiler -Macro $sanitizer -Body $body
        $expected = if ($pluginResult -like 'raw-*') { 'unknown' } else { $pluginResult }
        if ($final.code -ne 0 -or $final.report -cne $expected) { throw 'plugin-result-not-sanitized' }
    }
    # The original nonzero setup error survives both an existing worker result
    # and a diagnostic writer failure; no worker wait may replace the denial.
    $Installer = $denialFixture.executable
    $fake.workerDiagnostic.prerequisite = 'console-mismatch'
    $fake | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $rejected = $false
    try { Invoke-ManagerSetup -ResultPath $resultPath }
    catch { $rejected = $_.Exception.Message -match '^installer-failed: 3 diagnostics=' }
    if (-not $rejected) { throw 'setup-error-masked-by-worker-error' }
    $writer = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-ManagerWorkerDiagnostic' }, $true).Extent.Text
    try {
        function Write-ManagerWorkerDiagnostic { throw 'fixture-diagnostic-write-failed' }
        $rejected = $false
        try { Invoke-ManagerSetup -ResultPath $resultPath }
        catch { $rejected = $_.Exception.Message -match '^installer-failed: 3 diagnostics=' }
        if (-not $rejected) { throw 'diagnostic-write-failure-masked-original-setup-denial' }
    } finally { Invoke-Expression $writer }
    $Installer = $final.executable # Last sanitizer fixture exits successfully.
    $fake.ok = $true
    $fake | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $returned = Invoke-ManagerSetup -ResultPath $resultPath
    if ($returned -is [array] -or $returned.pid -ne 424242) { throw 'diagnostic-output-contaminated-worker-result' }
    Write-Output 'Windows compiled diagnostic parser mutation baseline and final passed; original setup failure preserved'
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
