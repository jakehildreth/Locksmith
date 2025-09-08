function Find-ESC1 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC1 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER ClientAuthEKUs
        A list of EKUs that can be used for client authentication.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
        $Results = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEKUs
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        $ClientAuthEKUs,
        [Parameter(Mandatory)]
        [int]$Mode,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
        ($_.'msPKI-Certificate-Name-Flag' -band 1) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
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
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and ($entry.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') ) -or
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
$($entry.IdentityReference) can provide a Subject Alternative Name (SAN) while
enrolling in this Client Authentication template, and enrollment does not require
Manager Approval.

The resultant certificate can be used by an attacker to authenticate as any
principal listed in the SAN up to and including Domain Admins, Enterprise Admins,
or Domain Controllers.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                    Fix                   = @"
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC1'
                }

                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }

                if ( $Mode -in @(1, 3, 4) ) {
                    Update-ESC1Remediation -Issue $Issue
                }

                $Issue
            }
        }
    }
}
