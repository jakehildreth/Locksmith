function Find-ESC3C2 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that match the second condition required for ESC3 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Targets (Get-Target)
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC3C2 -SafeUsers $SafeUsers
        $Results
    #>
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
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKU) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ($_.'msPKI-RA-Application-Policies' -match '1.3.6.1.4.1.311.20.2.1') -and
        ($_.'msPKI-RA-Signature' -eq 1)
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
If the holder of a SubCA, Any Purpose, or Enrollment Agent certificate requests
a certificate using this template, they will receive a certificate which allows
them to authenticate as $($entry.IdentityReference).

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                    Fix                   = @"
First, eliminate unused Enrollment Agent templates.
Then, tightly scope any Enrollment Agent templates that remain and:
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC3'
                    Condition             = 2
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}
