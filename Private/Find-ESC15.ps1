function Find-ESC15 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC15/EUKwu vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObjects -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $Results = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUser $SafeUsers
        $Results
    #>
    [alias('Find-EKUwu')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.'msPKI-Template-Schema-Version' -eq 1) -and
        ($_.Enabled)
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
$($_.Name) uses AD CS Template Schema Version 1, and $($entry.IdentityReference)
is allowed to enroll in this template.

If patches for CVE-2024-49019 have not been applied it may be possible to include
arbitrary Application Policies while enrolling in this template, including
Application Policies that permit Client Authentication or allow the creation
of Subordinate CAs.

More info:
  - https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019

"@
                    Fix                   = @"
<#
    Option 1: Manual Remediation
    Step 1: Identify if this template is Enabled on any CA.
    Step 2: If Enabled, identify if this template has recently been used to generate a certificate.
    Step 3a: If recently used, either restrict enrollment scope or convert to the template to Schema V2.
    Step 3b: If not recently used, unpublish the template from all CAs.
#>

<#
    Option 2: Scripted Remediation
    Step 1: Open an elevated Powershell session as an AD or PKI Admin
    Step 2: Run Unpublish-SchemaV1Templates.ps1
#>
Invoke-WebRequest -Uri https://gist.githubusercontent.com/jakehildreth/13c7d615adc905d317fc4379026ad28e/raw/Unpublish-SchemaV1Templates.ps1 | Invoke-Expression

"@
                    Revert                = '[TODO]'
                    Technique             = 'ESC15/EKUwu'
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}
