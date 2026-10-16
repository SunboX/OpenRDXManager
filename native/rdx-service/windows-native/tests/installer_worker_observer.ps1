# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
<# .SYNOPSIS Runs the real Manager worker branch against delayed installer observations; launches no process and changes no system policy. #>
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../../../../scripts/verify-windows-installation.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath).Path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'acceptance-script-syntax-error' }
$branch = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -ceq '$WorkerMode -eq ''Manager'''
}, $true)
if (-not $branch) { throw 'manager-worker-branch-missing' }
$body = $branch.Clauses[0].Item2.Extent.Text
$operation = [scriptblock]::Create($body.Substring(1, $body.Length - 2))
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('openrdx-worker-observer-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    foreach ($scenario in @('delayed', 'duplicate')) {
        & {
            param($operation, $scenario, $fixtureRoot)
            $manager = 'C:\Program Files\OpenRDXManager\OpenRDXManager.exe'
            $fixedRoot = Split-Path -Parent $manager
            $provisioner = "$fixedRoot\resources\native\windows\openrdx-local-install.exe"
            $ResultPath = Join-Path $fixtureRoot "$scenario.json"
            $workerDiagnostic = @{ prerequisite='ready' }
            $fixtureState = @{ queries=0; sleeps=0; selected=@() }
            <# .SYNOPSIS Models completed payload placement without inspecting or changing an installation. #>
            function Test-Path { return $true }
            <# .SYNOPSIS Bounds the fixture without sleeping or changing the production deadline. #>
            function Start-Sleep {
                $fixtureState.sleeps++
                if ($fixtureState.sleeps -gt 6) { throw 'observer-did-not-converge' }
            }
            <# .SYNOPSIS Rejects any verifier launch, reproducing its race with the real installer. #>
            function Start-Process { throw 'acceptance-worker-must-not-launch-manager' }
            <# .SYNOPSIS Supplies fixed process views; unrelated paths and renderer children cannot qualify. #>
            function Get-CimInstance {
                $fixtureState.queries++
                [pscustomobject]@{ ExecutablePath='C:\unrelated\OpenRDXManager.exe'; CommandLine=''; ProcessId=70 }
                [pscustomobject]@{ ExecutablePath=$manager; CommandLine='--type=renderer'; ProcessId=71 }
                if ($scenario -eq 'delayed' -and $fixtureState.queries -lt 3) { return }
                [pscustomobject]@{ ExecutablePath=$manager; CommandLine=''; ProcessId=81 }
                if ($scenario -eq 'duplicate' -and $fixtureState.queries -lt 3) {
                    [pscustomobject]@{ ExecutablePath=$manager; CommandLine=''; ProcessId=82 }
                }
            }
            <# .SYNOPSIS Records only the candidate selected by the actual worker branch. #>
            function Get-TokenDiagnostic([UInt32]$ProcessId) {
                $fixtureState.selected += $ProcessId
                return @{ fixturePid=$ProcessId }
            }
            & $operation
            $result = [IO.File]::ReadAllText($ResultPath) | ConvertFrom-Json
            if (-not $result.ok -or $result.pid -ne 81 -or $result.managerDiagnostic.fixturePid -ne 81 -or
                $fixtureState.queries -lt 3 -or $fixtureState.selected.Count -ne 1 -or $fixtureState.selected[0] -ne 81) {
                throw 'worker-did-not-observe-one-installer-manager'
            }
        } $operation $scenario $fixtureRoot
    }
    Write-Output 'OpenRDX installer worker observer passed: delayed launch, duplicate rejection, no verifier launch'
} finally { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
