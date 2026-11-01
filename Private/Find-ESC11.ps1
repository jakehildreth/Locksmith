function Find-ESC11 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC11 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService' and the InterfaceFlag set to 'No'. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique,
        Issue, Fix, and Revert.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Target (Get-Target)
        Find-ESC11 -ADCSObjects $ADCSObjects
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
            ($_.InterfaceFlag -eq 'No')
        } | ForEach-Object {
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Technique         = 'ESC11'
                Issue             = $_.InterfaceFlag
                Fix               = 'N/A'
                Revert            = 'N/A'
            }
            if ($_.InterfaceFlag -eq 'No') {
                $Issue.Issue = @'
The IF_ENFORCEENCRYPTICERTREQUEST flag is disabled on this Certification
Authority (CA). It is possible to relay NTLM authentication to the RPC interface
of this CA.

If the LAN Manager authentication level of any domain in this forest is 2 or
less, an attacker can coerce authentication from a Domain Controller (DC) to
receive a certificate which can be used to authenticate as that DC.

More info:
  - https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/

'@
                $Issue.Fix = @"
# Enable the flag
certutil -config '$CAFullname' -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
                $Issue.Revert = @"
# Disable the flag
certutil -config '$CAFullname' -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST

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
