function Find-ESC16 {
    <#
    .SYNOPSIS
        This script finds Active Directory Certificate Services (AD CS) Certification Authorities (CA) that have the ESC16 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService' and the szOID_NTDS_CA_SECURITY_EXT disabled. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique,
        Issue, Fix, and Revert.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    process {
        $ADCSObjects | Where-Object {
            ($_.objectClass -eq 'pKIEnrollmentService') -and
            ($_.DisableExtensionList -ne 'No')
        } | ForEach-Object {
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Issue             = $_.DisableExtensionList
                Fix               = 'N/A'
                Revert            = 'N/A'
                Technique         = 'ESC16'
            }
            if ($_.DisableExtensionList -eq 'Yes') {
                $Issue.Issue = @"
The Certification Authority (CA) $($_.CAFullName) has the szOID_NTDS_CA_SECURITY_EXT security extension disabled. When
this extension is disabled, every certificate issued from this template will be unable to reliably map a certificate to a
user or computer account's SID for authentication.

More info:
  - https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally

"@
                $Issue.Fix = @"
# Enable the flag
# TODO

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
                $Issue.Revert = @"
# Disable the flag
TODO

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
            }
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
            $Issue
        }
    }
}
