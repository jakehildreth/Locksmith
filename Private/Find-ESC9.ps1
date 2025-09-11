function Find-ESC9 {
    <#
    .SYNOPSIS
        This function finds Active Directory Certificate Services (AD CS)  objects that have the ESC9 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER UnsafeUsers
        Specifies the list of SIDs of safe users who should never have specific rights on the objects. This parameter is mandatory.

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
        [int]$Mode = 0,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
        ($_.'msPKI-Enrollment-Flag' -band 0x80000)
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
This Client Authentication template has the szOID_NTDS_CA_SECURITY_EXT security
extension disabled. Certificates issued from this template will not enforce
strong certificate binding. Depending on the current Certificate Binding
Enforcement level ESC6 status, it may be possible to request and receive
certificates that rely on weak (aka attacker-controllable) binding methods.

An attacker can abuse this weakness by:
1. Getting access to a user or computer account.
2. Modifying the user's userPrincipalName attribute (or the computer's dNSHostName attribute) to match a higher-privileged account.
3. Requesting a client authentication certificate from a template that w/ szOID_NTDS_CA_SECURITY_EXT disabled.
4. Using the client authentication certificiate to authenticate as the higher-privileged account.
5. Profiting.

More info:
  - ESC9 description: https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template
  - Strong Mapping/Enforcement Mode: https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

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
                    Technique             = 'ESC9'
                }

                if ( $Mode -in @(1, 3, 4) ) {
                    Update-ESC9Remediation -Issue $Issue
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}
