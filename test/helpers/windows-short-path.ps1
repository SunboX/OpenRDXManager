# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later

param([Parameter(Mandatory = $true)][string]$Target)
$ErrorActionPreference = 'Stop'
# Query the operating system's real alias; do not invent paths or change 8.3 policy.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class OpenRDXShortPath {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetShortPathNameW(string path, StringBuilder output, uint capacity);
}
'@
$buffer = [System.Text.StringBuilder]::new(32768)
$length = [OpenRDXShortPath]::GetShortPathNameW($Target, $buffer, 32768)
if ($length -eq 0 -or $length -ge 32768) { throw 'Cannot query the existing directory alias' }
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@{ shortPath = $buffer.ToString() } | ConvertTo-Json -Compress
