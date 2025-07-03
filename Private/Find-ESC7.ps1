function Find-ESC7 {
    <#
    .SYNOPSIS
        This script finds Active Directory Certificate Services (AD CS) Certificate Authorities (CA) that have the ESC7 vulnerability.

    .DESCRIPTION
        The script takes an array of AD CS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService'. If the CA objects have non-standard/unsafe principals as administrators or managers, an issue is created.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS objects to be processed. This parameter is mandatory.

    .PARAMETER UnsafeUsers
        Principals that should never be granted control of a CA.

    .PARAMETER SafeUsers
        Principals that are generally recognized as safe to control a CA.

    .PARAMETER SkipRisk
        Switch used when processing second-order risks.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching AD CS objects and their associated information.

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [switch]$SkipRisk
    )
    process {
        Write-Output $ADCSObjects -PipelineVariable object | Where-Object {
            ($object.objectClass -eq 'pKIEnrollmentService') -and $object.CAHostDistinguishedName -and
            ( ($object.CAAdministrator) -or ($object.CertificateManager) )
        } | ForEach-Object {
            Write-Output $object.CAAdministrator -PipelineVariable admin | ForEach-Object {
                <#
                    Checkout my change @jakehildreth
                    Get by a customer and by demo lab this issue
                    Exception calling "Translate" with "1" argument(s): "Some or all identity references could not be translated."
                #>
                if (($admin -match $env:USERDOMAIN) -or ($admin -match 'BUILTIN')) {
                    #write-host "Extanten from Mathias by CAAdministrator" -ForegroundColor DarkRed
                    #Write-Host "`$admin is $($admin)"
                    $SID = Convert-IdentityReferenceToSid -Object $admin
                    #write-host "`$SID of $($admin) is $($SID)"
                    if ($SID -notmatch $SafeUsers) {
                        $Issue = [pscustomobject]@{
                            Forest               = $object.CanonicalName.split('/')[0]
                            Name                 = $object.Name
                            DistinguishedName    = $object.DistinguishedName
                            IdentityReference    = $admin
                            IdentityReferenceSID = $SID
                            Right                = 'CA Administrator'
                            Issue                = @"
$admin has been granted CA Administrator rights on this Certification Authority (CA).

$admin has full control over this CA.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                            Fix                  = "Revoke CA Administrator rights from ${admin}."
                            Revert               = "Restore CA Administrator rights to ${admin}."
                            Technique            = 'ESC7'
                        }

                        if ($SkipRisk -eq $false) {
                            Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                        }

                        if ( $Mode -in @(1, 3, 4) ) {
                            Update-ESC7Remediation -Issue $Issue
                        }

                        $Issue
                    }
                }
            }

            Write-Output $object.CertificateManager -PipelineVariable admin | ForEach-Object {
                if (($admin -match $env:USERDOMAIN) -or ($admin -match 'BUILTIN')) {
                    #write-host "Extanten from Mathias by CertificateManager" -ForegroundColor DarkRed
                    #Write-Host "`$admin is $($admin)"
                    $SID = Convert-IdentityReferenceToSid -Object $admin
                    #write-host "`$SSID of $($admin) is $($SID)"
                    if ($SID -notmatch $SafeUsers) {
                        $Issue = [pscustomobject]@{
                            Forest               = $object.CanonicalName.split('/')[0]
                            Name                 = $object.Name
                            DistinguishedName    = $object.DistinguishedName
                            IdentityReference    = $admin
                            IdentityReferenceSID = $SID
                            Right                = 'Certificate Manager'
                            Issue                = @"
$admin has been granted Certificate Manager rights on this Certification Authority (CA).

$admin can approve pending certificate requests on this CA.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                            Fix                  = "Revoke Certificate Manager rights from ${admin}."
                            Revert               = "Restore Certificate Manager rights to ${admin}."
                            Technique            = 'ESC7'
                        }

                        if ($SkipRisk -eq $false) {
                            Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                        }

                        if ( $Mode -in @(1, 3, 4) ) {
                            Update-ESC7Remediation -Issue $Issue
                        }

                        $Issue
                    }
                }
            }
        }
    }
}
