# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
<#
.SYNOPSIS
Exercises the real unsigned installer on a disposable Windows machine with an active console.
.PARAMETER Installer
Absolute NSIS installer path. Existing installations and physical RDX devices are refused.
.PARAMETER Workspace
Checkout containing the installed-app verifier and its npm dependencies.
.PARAMETER NodePath
Ordinary Node executable used by the limited interactive acceptance process.
.PARAMETER WorkerMode
Internal scheduled-task operation; never supplies production trust paths or principals.
.PARAMETER ResultPath
Internal bounded result file in the exact per-run verification directory.
#>
param(
    [string]$Installer,
    [string]$Workspace = (Split-Path -Parent $PSScriptRoot),
    [string]$NodePath = (Get-Command node -ErrorAction SilentlyContinue).Source,
    [ValidateSet('', 'Manager', 'Acceptance', 'Portable')][string]$WorkerMode = '',
    [string]$ResultPath
)
$ErrorActionPreference = 'Stop'
$fixedRoot = 'C:\Program Files\OpenRDXManager'
$provisioner = "$fixedRoot\resources\native\windows\openrdx-local-install.exe"
$manager = "$fixedRoot\OpenRDXManager.exe"
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class OpenRDXConsole {
 [DllImport("kernel32.dll")] public static extern UInt32 WTSGetActiveConsoleSessionId();
 [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool WTSQuerySessionInformationW(IntPtr server, UInt32 session, int kind, out IntPtr value, out UInt32 bytes);
 [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr value);
}
/// <summary>Read-only process/token facts; every public field is a boolean.</summary>
public sealed class OpenRDXTokenFacts {
 public bool ElevationQueryOk, ElevationSizeMatch, Elevated;
 public bool SessionQueryOk, SessionSizeMatch, ProcessSessionQueryOk;
 public bool TokenMatchesProcessSession, TokenMatchesConsole, ProcessMatchesConsole;
 public bool ElevationTypeQueryOk, ElevationTypeSizeMatch, ElevationTypeDefault, ElevationTypeFull, ElevationTypeLimited;
 public bool LinkedTokenQueryOk, LinkedTokenSizeMatch, LinkedTokenAvailable;
}
/// <summary>Queries the exact selected process without granting or modifying access.</summary>
public static class OpenRDXTokenDiagnostics {
 /// <summary>Opens only a read-only query handle for the existing PID.</summary>
 [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr OpenProcess(UInt32 access, bool inherit, UInt32 pid);
 /// <summary>Opens only TOKEN_QUERY access on that pinned process.</summary>
 [DllImport("advapi32.dll", SetLastError=true)] private static extern bool OpenProcessToken(IntPtr process, UInt32 access, out IntPtr token);
 /// <summary>Reads an exact four-byte elevation or session output.</summary>
 [DllImport("advapi32.dll", SetLastError=true)] private static extern bool GetTokenInformation(IntPtr token, int kind, out UInt32 value, UInt32 length, out UInt32 returned);
 /// <summary>Queries the linked token handle without duplicating or launching with it.</summary>
 [DllImport("advapi32.dll", EntryPoint="GetTokenInformation", SetLastError=true)] private static extern bool GetLinkedTokenInformation(IntPtr token, int kind, out IntPtr value, UInt32 length, out UInt32 returned);
 /// <summary>Queries the existing process session without changing it.</summary>
 [DllImport("kernel32.dll", SetLastError=true)] private static extern bool ProcessIdToSessionId(UInt32 pid, out UInt32 session);
 /// <summary>Releases only handles opened by this diagnostic.</summary>
 [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
 /// <summary>Returns bounded facts only; query failures remain false and cannot authorize a process.</summary>
 public static OpenRDXTokenFacts Read(UInt32 pid) {
  var facts = new OpenRDXTokenFacts();
  IntPtr process = IntPtr.Zero, token = IntPtr.Zero, linkedToken = IntPtr.Zero;
  try {
   process = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
   if (process == IntPtr.Zero || !OpenProcessToken(process, 8, out token)) return facts; // TOKEN_QUERY
   UInt32 elevation, returned, tokenSession, processSession;
   facts.ElevationQueryOk = GetTokenInformation(token, 20, out elevation, 4, out returned); // TokenElevation
   facts.ElevationSizeMatch = facts.ElevationQueryOk && returned == 4;
   facts.Elevated = facts.ElevationSizeMatch && elevation != 0;
   facts.SessionQueryOk = GetTokenInformation(token, 12, out tokenSession, 4, out returned); // TokenSessionId
   facts.SessionSizeMatch = facts.SessionQueryOk && returned == 4;
   facts.ProcessSessionQueryOk = ProcessIdToSessionId(pid, out processSession);
   UInt32 console = OpenRDXConsole.WTSGetActiveConsoleSessionId();
   facts.TokenMatchesProcessSession = facts.SessionSizeMatch && facts.ProcessSessionQueryOk && tokenSession == processSession;
   facts.TokenMatchesConsole = facts.SessionSizeMatch && console != UInt32.MaxValue && tokenSession == console;
   facts.ProcessMatchesConsole = facts.ProcessSessionQueryOk && console != UInt32.MaxValue && processSession == console;
   UInt32 elevationType;
   facts.ElevationTypeQueryOk = GetTokenInformation(token, 18, out elevationType, 4, out returned); // TokenElevationType
   facts.ElevationTypeSizeMatch = facts.ElevationTypeQueryOk && returned == 4;
   facts.ElevationTypeDefault = facts.ElevationTypeSizeMatch && elevationType == 1;
   facts.ElevationTypeFull = facts.ElevationTypeSizeMatch && elevationType == 2;
   facts.ElevationTypeLimited = facts.ElevationTypeSizeMatch && elevationType == 3;
   facts.LinkedTokenQueryOk = GetLinkedTokenInformation(token, 19, out linkedToken, (UInt32)IntPtr.Size, out returned); // TokenLinkedToken
   // Failure does not transfer handle ownership. A successful query's handle is
   // owned even if a future API reports an unexpected size; always release it.
   // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_linked_token
   if (!facts.LinkedTokenQueryOk) linkedToken = IntPtr.Zero;
   facts.LinkedTokenSizeMatch = facts.LinkedTokenQueryOk && returned == (UInt32)IntPtr.Size;
   facts.LinkedTokenAvailable = facts.LinkedTokenSizeMatch && linkedToken != IntPtr.Zero;
   return facts;
  } catch { return facts; }
  finally { if (linkedToken != IntPtr.Zero) CloseHandle(linkedToken); if (token != IntPtr.Zero) CloseHandle(token); if (process != IntPtr.Zero) CloseHandle(process); }
 }
}
'@

<# .SYNOPSIS Reads boolean-only facts for an exact PID; never selects, launches, enrolls or authorizes it. .PARAMETER ProcessId Process already selected by the existing lifecycle. #>
function Get-TokenDiagnostic([UInt32]$ProcessId) {
    return [OpenRDXTokenDiagnostics]::Read($ProcessId)
}

<# .SYNOPSIS Reads UAC and the current user's equality with the enumerated local builtin Administrator; never returns identity or changes account/policy. #>
function Get-ConsoleContextDiagnostic {
    $facts = @{ UacQueryOk=$false; EnableLuaIsOne=$false; LocalBuiltinAdminQueryOk=$false; LocalBuiltinAdmin=$false }
    try {
        $value = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA
        $facts.UacQueryOk = $value -is [int] -or $value -is [uint32]
        $facts.EnableLuaIsOne = $facts.UacQueryOk -and $value -eq 1
    } catch {}
    try {
        # Get-LocalUser limits the comparison to the local SAM, avoiding a
        # domain Administrator with the same relative well-known account type.
        $builtin = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.IsWellKnown([Security.Principal.WellKnownSidType]::AccountAdministratorSid) })
        if ($builtin.Count -eq 1) {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            try {
                $facts.LocalBuiltinAdmin = $builtin[0].SID.Equals($identity.User)
                $facts.LocalBuiltinAdminQueryOk = $true
            } finally { $identity.Dispose() }
        }
    } catch {}
    return $facts
}

<# .SYNOPSIS Reads the exact registered task's run level; query failure is distinguished from a non-LUA result. .PARAMETER TaskName Exact verification-owned task. #>
function Get-TaskRunLevelDiagnostic([string]$TaskName) {
    $facts = @{ TaskRunLevelQueryOk=$false; TaskRunLevelIsLua=$false }
    try {
        $level = [string](Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).Principal.RunLevel
        $facts.TaskRunLevelQueryOk = $level -cin @('Limited', 'Highest')
        $facts.TaskRunLevelIsLua = $facts.TaskRunLevelQueryOk -and $level -ceq 'Limited'
    } catch {}
    return $facts
}

<# .SYNOPSIS Prints only boolean token context for a fixed subject; no token, identity or numeric enum leaves this boundary. .PARAMETER Subject Closed diagnostic subject. .PARAMETER Facts Read-only token query results. #>
function Write-TokenContextDiagnostic([ValidateSet('worker', 'worker-selected-manager')][string]$Subject, $Facts) {
    Write-Output ('OpenRDX token context: subject={0} type-query={1} type-size-match={2} type-default={3} type-full={4} type-limited={5} linked-query={6} linked-size-match={7} linked-available={8}' -f
        $Subject, [bool]$Facts.ElevationTypeQueryOk, [bool]$Facts.ElevationTypeSizeMatch, [bool]$Facts.ElevationTypeDefault, [bool]$Facts.ElevationTypeFull, [bool]$Facts.ElevationTypeLimited, [bool]$Facts.LinkedTokenQueryOk, [bool]$Facts.LinkedTokenSizeMatch, [bool]$Facts.LinkedTokenAvailable)
}

<# .SYNOPSIS Prints only reconstructed prerequisite tokens and boolean token facts, including on setup failure. .PARAMETER Path Exact owned worker result, read without waiting on failure. .PARAMETER Result Previously bounded worker result on success. #>
function Write-ManagerWorkerDiagnostic([string]$Path, $Result) {
    try {
        if ($null -eq $Result) {
            if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { Write-Output 'OpenRDX Manager worker: result=not-observed'; return }
            if ((Get-Item -LiteralPath $Path).Length -gt 65536) { Write-Output 'OpenRDX Manager worker: result=unbounded'; return }
            $Result = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
        }
        $prerequisite = 'unknown'
        if ($Result.workerDiagnostic.prerequisite -cin @('not-checked', 'console-mismatch', 'not-unelevated', 'ready')) { $prerequisite = $Result.workerDiagnostic.prerequisite }
        $worker = $Result.workerDiagnostic.facts
        Write-Output ('OpenRDX Manager worker: prerequisite={0} elevation-query={1} elevation-size-match={2} elevated={3} token-process-session-match={4} token-console-match={5}' -f
            $prerequisite, [bool]$worker.ElevationQueryOk, [bool]$worker.ElevationSizeMatch, [bool]$worker.Elevated, [bool]$worker.TokenMatchesProcessSession, [bool]$worker.TokenMatchesConsole)
        Write-TokenContextDiagnostic -Subject 'worker' -Facts $worker
        $context = $Result.workerDiagnostic.context
        Write-Output ('OpenRDX console context: uac-query={0} enablelua-is-one={1} local-builtin-admin-query={2} local-builtin-admin={3}' -f
            [bool]$context.UacQueryOk, [bool]$context.EnableLuaIsOne, [bool]$context.LocalBuiltinAdminQueryOk, [bool]$context.LocalBuiltinAdmin)
        if ($null -eq $Result.managerDiagnostic) { Write-Output 'OpenRDX worker-selected Manager: token=not-observed'; return }
        $facts = $Result.managerDiagnostic
        Write-Output ('OpenRDX worker-selected Manager: elevation-query={0} elevation-size-match={1} elevated={2} session-query={3} session-size-match={4} process-session-query={5} token-process-session-match={6} token-console-match={7} process-console-match={8}' -f
            [bool]$facts.ElevationQueryOk, [bool]$facts.ElevationSizeMatch, [bool]$facts.Elevated, [bool]$facts.SessionQueryOk, [bool]$facts.SessionSizeMatch, [bool]$facts.ProcessSessionQueryOk, [bool]$facts.TokenMatchesProcessSession, [bool]$facts.TokenMatchesConsole, [bool]$facts.ProcessMatchesConsole)
        Write-TokenContextDiagnostic -Subject 'worker-selected-manager' -Facts $facts
    } catch { Write-Output 'OpenRDX Manager worker: result=unavailable' }
}

<# .SYNOPSIS Runs the existing setup then existing worker wait; diagnostic failures never replace a setup exception. .PARAMETER ResultPath Exact Manager worker result. #>
function Invoke-ManagerSetup([string]$ResultPath) {
    try {
        Invoke-Setup | Write-Host
        $managerResult = Wait-Worker $ResultPath
        Write-ManagerWorkerDiagnostic -Result $managerResult | Write-Host
        return $managerResult
    }
    catch {
        $setupFailure = $_
        # Diagnostic IO is best-effort and cannot mask the original setup/worker error.
        try { Write-ManagerWorkerDiagnostic -Path $ResultPath | Write-Host } catch {}
        throw $setupFailure
    }
}

<# .SYNOPSIS Accepts complete removal or only the protected running remover scheduled for deletion at reboot. .PARAMETER RuntimeRoot Exact verification-owned runtime. .PARAMETER PendingDeletes Test-only captured OS rename operations; production reads the Session Manager journal. #>
function Assert-RemovedRuntime([string]$RuntimeRoot, [string[]]$PendingDeletes) {
    if (-not (Test-Path -LiteralPath $RuntimeRoot)) { return }
    $remaining = @(Get-ChildItem -LiteralPath $RuntimeRoot -Force)
    $self = Join-Path $RuntimeRoot 'Uninstall OpenRDXManager.exe'
    if ($remaining.Count -ne 1 -or $remaining[0].PSIsContainer -or $remaining[0].Name -cne 'Uninstall OpenRDXManager.exe' -or
        ($remaining[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'unexpected-runtime-removal-residue' }
    foreach ($path in @($RuntimeRoot, $self)) {
        $acl = Get-Acl -LiteralPath $path
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if ($owner -notin @('S-1-5-18', 'S-1-5-32-544') -or -not $acl.AreAccessRulesProtected -or $rules.Count -ne 4) { throw 'unprotected-runtime-removal-residue' }
        $expected = @{'S-1-5-18'=0x1f01ff; 'S-1-5-32-544'=0x1f01ff; 'S-1-5-19'=0x1200a9; 'S-1-5-32-545'=0x1200a9}
        $inheritance = if ($path -eq $RuntimeRoot) { 3 } else { 0 }
        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value
            if (-not $expected.ContainsKey($sid) -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or
                [int64]$rule.FileSystemRights -ne $expected[$sid] -or [int]$rule.InheritanceFlags -ne $inheritance -or [int]$rule.PropagationFlags -ne 0) {
                throw 'noncanonical-runtime-removal-residue'
            }
            $expected.Remove($sid)
        }
    }
    if ($null -eq $PendingDeletes) {
        $PendingDeletes = @((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
    }
    $scheduled = $false
    for ($index = 0; $index + 1 -lt $PendingDeletes.Count; $index += 2) {
        # The Windows VM records this delayed deletion with a *1 prefix.
        # Accept only that observed token or the unflagged exact NT pathname.
        if (($PendingDeletes[$index] -ieq "\??\$self" -or $PendingDeletes[$index] -ieq "*1\??\$self") -and $PendingDeletes[$index + 1] -eq '') { $scheduled = $true }
    }
    if (-not $scheduled) { throw 'pending-own-remover-delete-unconfirmed' }
    Write-Output 'owned-remover-only-residue-scheduled-for-reboot'
}

<# .SYNOPSIS Reads the kernel's current console account; rejects absent or disconnected consoles. #>
function Get-ConsoleAccount {
    $session = [OpenRDXConsole]::WTSGetActiveConsoleSessionId()
    if ($session -eq [UInt32]::MaxValue -or $session -eq 0) { throw 'active-console-required' }
    $parts = @()
    foreach ($kind in @(7, 5)) {
        $pointer = [IntPtr]::Zero; $size = [UInt32]0
        if (-not [OpenRDXConsole]::WTSQuerySessionInformationW([IntPtr]::Zero, $session, $kind, [ref]$pointer, [ref]$size)) { throw 'console-account-unavailable' }
        try {
            if ($size -gt 4096) { throw 'console-account-unbounded' }
            $parts += [Runtime.InteropServices.Marshal]::PtrToStringUni($pointer)
        } finally { [OpenRDXConsole]::WTSFreeMemory($pointer) }
    }
    if ([string]::IsNullOrWhiteSpace($parts[1])) { throw 'interactive-console-user-required' }
    return "$($parts[0])\$($parts[1])"
}

<# .SYNOPSIS Captures native stdout/stderr and its actual exit status on Windows PowerShell 5.1. .PARAMETER Executable Exact test-owned program. .PARAMETER Arguments Its bounded operation arguments. #>
function Invoke-CapturedProgram([string]$Executable, [string[]]$Arguments) {
    # PowerShell 5.1 promotes redirected native stderr to ErrorRecords. Preserve
    # expected denials and harmless diagnostics until the caller checks exitCode.
    $preference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $Executable @Arguments 2>&1 | ForEach-Object { $_.ToString() } | Out-String
        $code = $LASTEXITCODE
        return @{ output = $output; exitCode = $code }
    } finally { $ErrorActionPreference = $preference }
}

if ($WorkerMode) {
    # Task Scheduler must supply the actual interactive limited token. A SYSTEM
    # session or elevated GUI cannot count as installed Manager authentication.
    $workerDiagnostic = @{ prerequisite = 'not-checked'; facts = Get-TokenDiagnostic -ProcessId $PID; context = Get-ConsoleContextDiagnostic }
    $managerDiagnostic = $null
    try {
        if ([Diagnostics.Process]::GetCurrentProcess().SessionId -ne [OpenRDXConsole]::WTSGetActiveConsoleSessionId()) { $workerDiagnostic.prerequisite = 'console-mismatch'; throw 'worker-console-mismatch' }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $workerDiagnostic.prerequisite = 'not-unelevated'; throw 'worker-must-be-unelevated' }
        $workerDiagnostic.prerequisite = 'ready'
        if ($WorkerMode -eq 'Manager') {
            $deadline = [DateTime]::UtcNow.AddSeconds(120)
            while (-not (Test-Path -LiteralPath $manager) -or -not (Test-Path -LiteralPath $provisioner) -or -not (Test-Path -LiteralPath "$fixedRoot\resources\local-trust\runtime.json")) {
                if ([DateTime]::UtcNow -ge $deadline) { throw 'installed-manager-placement-timeout' }
                Start-Sleep -Milliseconds 250
            }
            $candidates = @(Get-CimInstance Win32_Process -Filter "Name='OpenRDXManager.exe'" | Where-Object { $_.ExecutablePath -eq $manager -and $_.CommandLine -notmatch '--type=' })
            if ($candidates.Count -eq 0) { Start-Process -FilePath $manager | Out-Null }
            do {
                Start-Sleep -Milliseconds 500
                $candidates = @(Get-CimInstance Win32_Process -Filter "Name='OpenRDXManager.exe'" | Where-Object { $_.ExecutablePath -eq $manager -and $_.CommandLine -notmatch '--type=' })
                if ([DateTime]::UtcNow -ge $deadline) { throw 'stable-installed-manager-pid-timeout' }
            } while ($candidates.Count -ne 1)
            $managerDiagnostic = Get-TokenDiagnostic -ProcessId $candidates[0].ProcessId
            @{ ok = $true; pid = $candidates[0].ProcessId; workerDiagnostic = $workerDiagnostic; managerDiagnostic = $managerDiagnostic } | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
        } elseif ($WorkerMode -eq 'Portable') {
            Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue
            $copy = Join-Path (Split-Path -Parent $ResultPath) 'portable\OpenRDXManager\OpenRDXManager.exe'
            $source = @'
import {execFile} from 'node:child_process'; import {promisify} from 'node:util';
try { let output=''; try { const result=await promisify(execFile)(process.argv[1],['--service-auth-test','--user-data-dir='+process.argv[2]],{timeout:60000,maxBuffer:8388608});output=result.stdout+result.stderr; } catch(error) { if(error.killed)throw error;output=(error.stdout||'')+(error.stderr||''); } if(output.includes('OpenRDXManager installed service authentication passed:')||!output.includes('OpenRDXManager service readiness:'))throw Error('portable-rejection-unconfirmed');console.log('Windows copied Manager privileged authentication denied'); } catch(error) { console.error(error);process.exitCode=1; }
'@
            $nativeResult = Invoke-CapturedProgram -Executable $NodePath -Arguments @('--input-type=module', '-e', $source, $copy, (Join-Path (Split-Path -Parent $ResultPath) 'portable-profile'))
            $output = $nativeResult.output
            if ($nativeResult.exitCode -ne 0) { throw "portable-negative-failed: $output" }
            @{ ok = $true; output = $output } | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
        } else {
            Set-Location -LiteralPath $Workspace
            Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue
            $nativeResult = Invoke-CapturedProgram -Executable $NodePath -Arguments @("$Workspace\scripts\verify-packaged-app.mjs", '--installed', '--require-service')
            $output = $nativeResult.output
            if ($nativeResult.exitCode -ne 0 -or $output -notmatch 'OpenRDXManager installed service authentication passed: platform=win32') { throw "installed-authentication-failed: $output" }
            @{ ok = $true; output = $output } | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
        }
    } catch {
        @{ ok = $false; error = $_.Exception.Message; workerDiagnostic = $workerDiagnostic; managerDiagnostic = $managerDiagnostic } | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
        exit 1
    }
    exit 0
}

<# .SYNOPSIS Runs an exact fixed installer action and requires its exit status. .PARAMETER Arguments Closed native action arguments. #>
function Invoke-LocalAction([string[]]$Arguments) {
    $result = Invoke-CapturedProgram -Executable $provisioner -Arguments $Arguments
    Write-Output $result.output
    if ($result.exitCode -ne 0) { throw "native-action-failed: $($Arguments[1]) code=$($result.exitCode)" }
}
<# .SYNOPSIS Reads at most 65,536 characters of UTF-8 text from an exact verification-owned process log. .PARAMETER Path Captured stdout or stderr file. #>
function Read-SetupDiagnostic([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true, 1024)
    try {
        $buffer = New-Object char[] 65536
        $count = $reader.ReadBlock($buffer, 0, $buffer.Length)
        $output = New-Object string($buffer, 0, $count)
        if (-not $reader.EndOfStream) { $output += '[diagnostic-output-truncated]' }
        return $output
    } finally { $reader.Dispose(); $stream.Dispose() }
}
<# .SYNOPSIS Runs bounded NSIS setup, captures inherited GUI diagnostics and requires its actual exit status. .PARAMETER Executable Exact verification target, defaults to the requested installer. .PARAMETER Arguments Its fixed operation, defaults to silent setup. .PARAMETER TimeoutMilliseconds Bounded wait; tests use a shorter interval to prove timeout handling. #>
function Invoke-Setup([string]$Executable = $Installer, [string]$Arguments = '/S', [int]$TimeoutMilliseconds = 120000) {
    $token = [Guid]::NewGuid().ToString('N')
    $stdout = Join-Path $runDirectory "setup-$token.stdout"
    $stderr = Join-Path $runDirectory "setup-$token.stderr"
    $process = $null
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
        # Pin the handle before exit: Windows PowerShell 5.1 otherwise loses ExitCode.
        $handle = $process.Handle
        $finished = $process.WaitForExit($TimeoutMilliseconds)
        if (-not $finished) { $process.Kill(); $null = $process.WaitForExit(5000) }
        $output = (Read-SetupDiagnostic $stdout) + (Read-SetupDiagnostic $stderr)
        Write-Output $output
        if (-not $finished) { throw "installer-timeout: diagnostics=$output" }
        if ($process.ExitCode -ne 0) { throw "installer-failed: $($process.ExitCode) diagnostics=$output" }
    } finally {
        if ($process) { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}
<# .SYNOPSIS Waits for bounded output from the exact limited interactive task. #>
function Wait-Worker([string]$Path, [switch]$AllowFailure) {
    $deadline = [DateTime]::UtcNow.AddSeconds(150)
    while (-not (Test-Path -LiteralPath $Path)) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'interactive-task-timeout' }
        Start-Sleep -Milliseconds 250
    }
    if ((Get-Item -LiteralPath $Path).Length -gt 65536) { throw 'interactive-result-unbounded' }
    $result = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if (-not $result.ok -and -not $AllowFailure) { throw "interactive-task-failed: $($result.error)" }
    return $result
}
<# .SYNOPSIS Launches the registered task with the console user's Interactive limited token. #>
function Start-Worker([string]$Mode) {
    $result = Join-Path $runDirectory "$Mode-$([Guid]::NewGuid()).json"
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -WorkerMode {1} -Workspace "{2}" -NodePath "{3}" -ResultPath "{4}"' -f $PSCommandPath, $Mode, $Workspace, $NodePath, $result
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $consoleAccount -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    # Read back the actual registration rather than inferring it from the request.
    # Diagnostic failure cannot prevent the original launch or change its result.
    try {
        $taskFacts = Get-TaskRunLevelDiagnostic -TaskName $taskName
        Write-Host ('OpenRDX interactive task: runlevel-query={0} runlevel-is-lua={1}' -f [bool]$taskFacts.TaskRunLevelQueryOk, [bool]$taskFacts.TaskRunLevelIsLua)
    } catch {}
    Start-ScheduledTask -TaskName $taskName
    return $result
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'elevated-disposable-test-required' }
if (-not $Installer -or -not [IO.Path]::IsPathRooted($Installer) -or -not (Test-Path -LiteralPath $Installer -PathType Leaf)) { throw 'absolute-installer-required' }
if (Test-Path -LiteralPath $fixedRoot) { throw 'existing-runtime-preserved-use-disposable-machine' }
if (Test-Path -LiteralPath 'C:\ProgramData\OpenRDXManager') { throw 'existing-openrdx-data-preserved' }
if (Get-Service -Name OpenRDXHardwareService -ErrorAction SilentlyContinue) { throw 'existing-service-preserved' }
if (Get-CimInstance Win32_DiskDrive | Where-Object { $_.Model -match 'RDX' }) { throw 'physical-rdx-test-not-authorized-by-ci' }
$consoleAccount = Get-ConsoleAccount
$runDirectory = Join-Path ([IO.Path]::GetTempPath()) "openrdx-install-verification-$([Guid]::NewGuid())"
New-Item -ItemType Directory -Path $runDirectory | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @($consoleAccount, 'Modify'))) {
    $sid = if ($entry[0] -like 'S-*') { New-Object Security.Principal.SecurityIdentifier($entry[0]) } else { (New-Object Security.Principal.NTAccount($entry[0])).Translate([Security.Principal.SecurityIdentifier]) }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $entry[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $runDirectory -AclObject $acl
$taskName = "OpenRDX-LocalInstall-Verification-$([Guid]::NewGuid())"
$managerPid = $null
$backup = $null
try {
    # The limited console task waits for NSIS file placement, allowing the
    # elevated installer to pin a real Manager without selecting a raw SID.
    $resultPath = Start-Worker 'Manager'
    $managerPid = (Invoke-ManagerSetup -ResultPath $resultPath).pid
    Invoke-LocalAction -Arguments @('--action', 'verify', '--manager-process-id', "$managerPid")
    Stop-Process -Id $managerPid -ErrorAction Stop
    $managerPid = $null
    $acceptance = Wait-Worker (Start-Worker 'Acceptance')
    Write-Output $acceptance.output

    # Close the verified service while preserving enrollment, so tamper tests
    # exercise hash rejection rather than retained-handle write denial or absence.
    Stop-Service -Name OpenRDXHardwareService -ErrorAction Stop
    (Get-Service -Name OpenRDXHardwareService).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
    $portable = Join-Path $runDirectory 'portable'
    New-Item -ItemType Directory -Path $portable | Out-Null
    Copy-Item -LiteralPath $fixedRoot -Destination $portable -Recurse
    Write-Output (Wait-Worker (Start-Worker 'Portable')).output

    # Harmless JSON whitespace changes a final enrolled hash while permitting
    # Electron to launch and report its native authentication denial.
    $json = Get-ChildItem -LiteralPath "$fixedRoot\resources\app.asar.unpacked" -Filter package.json -File -Recurse | Sort-Object FullName | Select-Object -First 1
    if (-not $json -or $json.Length -gt 1048576) { throw 'bounded-runtime-json-fixture-required' }
    $target = $json.FullName
    $backup = [IO.File]::ReadAllBytes($target)
    $changed = New-Object byte[] ($backup.Length + 1)
    [Array]::Copy($backup, $changed, $backup.Length)
    $changed[$changed.Length - 1] = 32
    [IO.File]::WriteAllBytes($target, $changed)
    $tamperedResult = Invoke-CapturedProgram -Executable $provisioner -Arguments @('--action', 'verify')
    Write-Output $tamperedResult.output
    if ($tamperedResult.exitCode -eq 0) { throw 'tampered-runtime-was-accepted' }
    $negative = Wait-Worker (Start-Worker 'Acceptance') -AllowFailure
    if ($negative.ok -or $negative.error -match 'installed service authentication passed: platform=win32') { throw 'tampered-installed-manager-authenticated' }
    # Repair uses incoming administrator-selected setup to replace corrupt files;
    # original bytes are restored only on failure, never to make Repair pass.
    $resultPath = Start-Worker 'Manager'
    $managerPid = (Invoke-ManagerSetup -ResultPath $resultPath).pid
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($target)) -ne [Convert]::ToBase64String($backup)) { throw 'installer-repair-did-not-restore-final-content' }
    $backup = $null
    Invoke-LocalAction -Arguments @('--action', 'repair', '--manager-process-id', "$managerPid")
    Invoke-LocalAction -Arguments @('--action', 'verify', '--manager-process-id', "$managerPid")
    Stop-Process -Id $managerPid -ErrorAction Stop
    $managerPid = $null
    Write-Output (Wait-Worker (Start-Worker 'Acceptance')).output
    Invoke-LocalAction -Arguments @('--action', 'prepare')

    $resultPath = Start-Worker 'Manager'
    $managerPid = (Invoke-ManagerSetup -ResultPath $resultPath).pid
    Invoke-LocalAction -Arguments @('--action', 'verify', '--manager-process-id', "$managerPid")
    Stop-Process -Id $managerPid -ErrorAction Stop
    $managerPid = $null
    Write-Output (Wait-Worker (Start-Worker 'Acceptance')).output
    Invoke-LocalAction -Arguments @('--action', 'prepare')
    Invoke-LocalAction -Arguments @('--action', 'remove')
    if (Get-Service -Name OpenRDXHardwareService -ErrorAction SilentlyContinue) { throw 'service-removal-unconfirmed' }
    if (Test-Path -LiteralPath 'C:\ProgramData\OpenRDXManager\LocalTrust\runtime.json') { throw 'enrollment-removal-unconfirmed' }
    $uninstaller = Start-Process -FilePath "$fixedRoot\Uninstall OpenRDXManager.exe" -ArgumentList '/S' -PassThru
    if (-not $uninstaller.WaitForExit(120000) -or $uninstaller.ExitCode -ne 0) { throw 'nsis-uninstall-failed' }
    Assert-RemovedRuntime -RuntimeRoot $fixedRoot
    Write-Output 'OpenRDX Windows installation acceptance passed: clean, repair, upgrade, tamper-denied, copied-manager-denied, owned-removal'
} finally {
    if ($backup) { [IO.File]::WriteAllBytes($target, $backup) }
    if ($managerPid) { Stop-Process -Id $managerPid -ErrorAction SilentlyContinue }
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
