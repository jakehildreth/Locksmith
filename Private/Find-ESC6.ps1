function Find-ESC6 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC6 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService' and the SANFlag set to 'Yes'. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique,
        Issue, Fix, and Revert. A CA whose SANFlag is null (not Reachable, or the read failed) is skipped.
        Find-AvailabilityIssue reports it.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Results = $ADCSObjects | Find-ESC6
        $Results
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
            ($_.SANFlag -eq 'Yes')
        } | ForEach-Object {
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                CAFullname        = $CAFullName
                DistinguishedName = $_.DistinguishedName
                Issue             = $_.SANFlag
                Fix               = 'N/A'
                Revert            = 'N/A'
                Technique         = 'ESC6'
            }
            if ($_.SANFlag -eq 'Yes') {
                $Issue.Issue = @"
The dangerous EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled on $CAFullname.
All templates enabled on this CA will accept a Subject Alternative Name (SAN)
during enrollment even if the template is not specifically configured to allow a SAN.

As of May 2022, Microsoft has neutered this situation by requiring all SANs to
be strongly mapped to certificates.

However, if strong mapping has been explicitly disabled on Domain Controllers,
this configuration remains vulnerable to privilege escalation attacks.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2
  - https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

"@
                $Issue.Fix = @"
# Disable the flag
certutil -config '$CAFullname' -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
                $Issue.Revert = @"
# Enable the flag
certutil -config '$CAFullname' -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

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
