# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later

param([Parameter(Mandatory = $true)][string]$Target, [string]$Mode = 'inspect')
$ErrorActionPreference = 'Stop'
# Independent OS ACL evidence; never emit account names, SIDs or log contents.
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($Mode -eq 'private-link-as-user') {
    # icacls /L operates on the link itself. Run before any path-based .NET ACL
    # access, which could follow and modify the credential fixture's target.
    # Explicit, non-inherited access survives the production parent's hardening.
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
    $icacls = 'C:\Windows\System32\icacls.exe'
    $principal = '*' + $user.Value
    $operations = @(
        @{ Name = '/grant:r'; Value = $principal + ':F' },
        @{ Name = '/inheritancelevel:r'; Value = $null },
        @{ Name = '/setowner'; Value = $principal }
    )
    foreach ($operation in $operations) {
        $arguments = @($Target, $operation.Name)
        if ($operation.Value) { $arguments += $operation.Value }
        $arguments += @('/L', '/Q')
        try {
            & $icacls @arguments > $null 2>&1
            if ($LASTEXITCODE -ne 0) { throw 'Link ACL setup failed' }
        } catch {
            throw 'Could not prepare isolated symbolic-link ACL'
        }
    }
    exit
}
$isDirectory = [System.IO.Directory]::Exists($Target)
$acl = if ($isDirectory) {
    [System.IO.Directory]::GetAccessControl($Target)
} else {
    [System.IO.File]::GetAccessControl($Target)
}
if ($Mode -eq 'own-as-user' -or $Mode -eq 'private-as-user') {
    # Elevated test runners default new filesystem objects to Administrators.
    # Model a desktop user's existing files without relaxing production checks.
    if ($Mode -eq 'private-as-user') {
        # A parent with non-inheritable private rules gives newly created test
        # files no readable inherited ACE. Set explicit access only in setup.
        $acl = if ($isDirectory) {
            [System.Security.AccessControl.DirectorySecurity]::new()
        } else {
            [System.Security.AccessControl.FileSecurity]::new()
        }
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner($user)
    if ($isDirectory) {
        [System.IO.Directory]::SetAccessControl($Target, $acl)
    } else {
        [System.IO.File]::SetAccessControl($Target, $acl)
    }
    exit
}
if ($Mode -eq 'make-public') {
    $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($everyone, 'Read', 'Allow')
    $acl.AddAccessRule($rule)
    if ($isDirectory) {
        [System.IO.Directory]::SetAccessControl($Target, $acl)
    } else {
        [System.IO.File]::SetAccessControl($Target, $acl)
    }
    exit
}
if ($Mode -ne 'inspect') { throw 'Unexpected ACL diagnostic mode' }
$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
$ownerMatches = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Equals($user)
$private = $ownerMatches -and $acl.AreAccessRulesProtected -and $rules.Count -eq 1
if ($private) {
    $rule = $rules[0]
    $private = $rule.IdentityReference.Equals($user) -and
        $rule.AccessControlType -eq 'Allow' -and
        $rule.FileSystemRights -eq 'FullControl' -and
        $rule.InheritanceFlags -eq 'None' -and -not $rule.IsInherited
}
@{ private = [bool]$private; ownerMatches = [bool]$ownerMatches; ruleCount = $rules.Count } | ConvertTo-Json -Compress
