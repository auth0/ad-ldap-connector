<#
This script limits file permissions for the specified install directory.

This limits access to the install directory as follows:
 - Local Administrators: Full Control for entire install directory
 - Connector and Admin Console services: Modify permissions for the ./data directory. Read/Execute for the rest of
    the install directory. This lets these services run / execute files in the install directory but only modify
    files in the ./data directory, where logs, config and certs etc. are stored.
#>

$InstallDirectory = Join-Path $PSScriptRoot ".." -Resolve

function Set-Permissions
{
    param (
        [string] $Path,
        [System.Security.AccessControl.FileSystemAccessRule[]] $rules,
        [switch] $Recurse
    )
    $acl = Get-Acl -Path $Path

    # Block permission inheritance from C:\ (True = Block, False = Remove existing inherited rules)
    $acl.SetAccessRuleProtection($true, $false)

    # SetAccessRuleProtection only strips *inherited* ACEs. It does NOT remove pre-existing
    # *explicit* ACEs, so a leftover grant (e.g. the interactive user picking up Full Control on a
    # directory created in user context during install) would survive and, because an individual
    # user SID is not filtered by UAC, let that user edit install files without elevating. Rebuild
    # the DACL from scratch and add back only the ACEs we want.
    foreach ($existing in @($acl.Access)) {
        [void]$acl.RemoveAccessRule($existing)
    }

    # Assign ownership to the Administrators group rather than the interactive user who ran the
    # installer. An owner has implicit READ_CONTROL / WRITE_DAC regardless of UAC token filtering,
    # so if an individual admin owns these files they can modify (or re-DAC) them without elevating.
    # With the owner set to a group whose SID is deny-only in the filtered (un-elevated) token,
    # owner rights only take effect from an elevated process.
    $acl.SetOwner([System.Security.Principal.NTAccount]"BUILTIN\Administrators")

    foreach ($rule in $rules) {
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl

    if ($Recurse) {
        # Apply per-child but do not let a single failure (e.g. a locked file or an over-MAX_PATH
        # path) throw and abort the whole install. Log and continue so the ACL is applied as widely
        # as possible; the children still inherit the parent's rebuilt DACL regardless.
        Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Set-Acl -Path $_.FullName -AclObject $acl
            } catch {
                Write-Warning "Could not set ACL on $($_.FullName): $($_.Exception.Message)"
            }
        }
    }
}

# Define the granular rights that match 'Modify' without 'Execute'
# This lets us write to the ./data directory but not have any execute permissions there. Reduces attack surface in
# case of compromise of the Connector or Admin Console services, since an attacker would not be able to execute
# any malicious files dropped in the ./data directory.
$modifyRights = [System.Security.AccessControl.FileSystemRights]::Read -bor `
                [System.Security.AccessControl.FileSystemRights]::Write -bor `
                [System.Security.AccessControl.FileSystemRights]::Delete -bor `
                [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

# Define inheritance and propagation flags
$inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]"None"

# Full access rule for the OS / SYSTEM account. Because we now rebuild the DACL from scratch,
# SYSTEM must be granted explicitly. Windows services here run as virtual accounts, but SYSTEM is
# still required for servicing, and its SID is not something a normal interactive user holds.
$systemFullAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
"NT AUTHORITY\SYSTEM", "FullControl", $inheritance, $propagation, "Allow")

# Full access rule for local Administrators (Full Control over folder, subfolders, and files)
$adminFullAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
"BUILTIN\Administrators", "FullControl", $inheritance, $propagation, "Allow")

# Modify rule for Connector Virtual Service Account
$connectorServiceModifyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
"NT SERVICE\Auth0 ADLDAP", $modifyRights, $inheritance, $propagation, "Allow")

# Read / Execute rule for Connector Virtual Service Account (for files it needs to execute but not modify)
$connectorServiceReadExecuteRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
"NT SERVICE\Auth0 ADLDAP", "ReadAndExecute", $inheritance, $propagation, "Allow")

# Modify rule for Admin Console Virtual Service Account
$adminServiceModifyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
"NT SERVICE\Auth0 ADLDAP Admin", $modifyRights, $inheritance, $propagation, "Allow")

# Read / Execute rule for Admin Console Virtual Service Account (for files it needs to execute but not modify)
$adminServiceReadExecuteRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
"NT SERVICE\Auth0 ADLDAP Admin", "ReadAndExecute", $inheritance, $propagation, "Allow")


Set-Permissions -Path $InstallDirectory -rules @($systemFullAccessRule, $adminFullAccessRule, $connectorServiceReadExecuteRule, $adminServiceReadExecuteRule)
Set-Permissions -Path "$InstallDirectory\data" -rules @($systemFullAccessRule, $adminFullAccessRule, $connectorServiceModifyRule, $adminServiceModifyRule) -Recurse
Set-Permissions -Path "$InstallDirectory\node_modules\win-ca\pem" -rules @($systemFullAccessRule, $adminFullAccessRule, $connectorServiceModifyRule, $adminServiceModifyRule) -Recurse
