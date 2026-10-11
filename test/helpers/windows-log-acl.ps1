# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later

param([Parameter(Mandatory = $true)][string]$Target, [string]$Mode = 'inspect')
$ErrorActionPreference = 'Stop'
# Independent OS ACL evidence; never emit account names, SIDs or log contents.
$isDirectory = [System.IO.Directory]::Exists($Target)
$acl = if ($isDirectory) {
    [System.IO.Directory]::GetAccessControl($Target)
} else {
    [System.IO.File]::GetAccessControl($Target)
}
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
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
