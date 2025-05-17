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
        $ADCSObjects | Where-Object {
            ($_.objectClass -eq 'pKIEnrollmentService') -and
            ( ($_.CAAdministrator) -or ($_.CertificateManager) )
        } | ForEach-Object {
            $UnsafeCAAdministrators = Write-Output $_.CAAdministrator -PipelineVariable admin | ForEach-Object {
                $SID = Convert-IdentityReferenceToSid -Object $admin
                if ($SID -notmatch $SafeUsers) {
                    $admin
                }
            }
            $UnsafeCertificateManagers = Write-Output $_.CertificateManager -PipelineVariable manager | ForEach-Object {
                $SID = Convert-IdentityReferenceToSid -Object $manager
                if ($SID -notmatch $SafeUsers) {
                    $manager
                }
            }
            if ($UnsafeCAAdministrators -or $UnsafeCertificateManagers) {
                $Issue = [pscustomobject]@{
                    Forest             = $_.CanonicalName.split('/')[0]
                    Name               = $_.Name
                    DistinguishedName  = $_.DistinguishedName
                    CAAdministrator    = $_.CAAdministrator
                    CertificateManager = $_.CertificateManager
                    Issue              = $null
                    Fix                = $null
                    Revert             = $null
                    Technique          = 'ESC7'
                }
                if ($UnsafeCAAdministrators) {
                    $Issue.Issue = $Issue.Issue + @"
Unexpected prinicipals ($($UnsafeCAAdministrators -join ', ')) are granted "CA Administrator" rights on this Certification Authority.

"@
                    $Issue.Fix = $Issue.Fix + @"
Revoke CA Administrator rights from $($UnsafeCAAdministrators -join ', ')

"@
                    $Issue.Revert = $Issue.Revert + @"
Reinstate CA Administrator rights for $($UnsafeCAAdministrators -join ', ')

"@
                }
                if ($UnsafeCertificateManagers) {
                    $Issue.Issue = $Issue.Issue + @"
Unexpected prinicipals ($($UnsafeCertificateManagers -join ', ')) are granted "Certificate Manager" rights on this Certification Authority.

"@
                    $Issue.Fix = $Issue.Fix + @"
Revoke CA Administrator rights from $($UnsafeCertificateManagers -join ', ')

"@
                    $Issue.Revert = $Issue.Revert + @"
Reinstate CA Administrator rights for $($UnsafeCertificateManagers -join ', ')

"@
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue.Issue = $Issue.Issue + @"

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                $Issue
            }
        }
    }
}
