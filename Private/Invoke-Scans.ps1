function Invoke-Scans {
    <#
    .SYNOPSIS
        Invoke-Scans.ps1 is a script that performs various scans on ADCS (Active Directory Certificate Services) objects.

    .PARAMETER Scans
        Specifies the type of scans to perform. Multiple scan options can be provided as an array. The default value is 'All'.
        The available scan options are: 'Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'ESC9', 'ESC11',
            'ESC13', 'ESC15, 'EKUwu', 'ESC16', 'ESC17', 'All', 'PromptMe'.

    .NOTES
        - The script requires the following functions to be defined: Find-AuditingIssue, Find-ESC1, Find-ESC2, Find-ESC3C1,
          Find-ESC3C2, Find-ESC4, Find-ESC5, Find-ESC6, Find-ESC8, Find-ESC9, Find-ESC11, Find-ESC13, Find-ESC15, Find-ESC16
        - The script uses Out-GridView or Out-ConsoleGridView for interactive selection when the 'PromptMe' scan option is chosen.
        - The script returns a hash table containing the results of the scans.

    .EXAMPLE
    Invoke-Scans
    # Perform all scans

    .EXAMPLE
    Invoke-Scans -Scans 'Auditing', 'ESC1'
    # Perform only the 'Auditing' and 'ESC1' scans

    .EXAMPLE
    Invoke-Scans -Scans 'PromptMe'
    # Prompt the user to select the scans to perform
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Performing multiple scans.')]
    param (
        # Could split Scans and PromptMe into separate parameter sets.
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$ClientAuthEkus,
        [Parameter(Mandatory)]
        [string]$ServerAuthEkus,
        [Parameter(Mandatory)]
        [string]$DangerousRights,
        [Parameter(Mandatory)]
        [string]$EnrollmentAgentEKU,
        [Parameter(Mandatory)]
        [int]$Mode,
        [Parameter(Mandatory)]
        [string]$SafeObjectTypes,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$SafeOwners,
        [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'EKUwu', 'ESC16', 'ESC17', 'All', 'PromptMe')]
        [array]$Scans = 'All',
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$PreferredOwner
    )

    if ( $Scans -eq 'PromptMe' ) {
        $GridViewTitle = 'Select the tests to run and press Enter or click OK to continue...'

        # Check for Out-GridView or Out-ConsoleGridView
        if ((Get-Command Out-ConsoleGridView -ErrorAction SilentlyContinue) -and ($PSVersionTable.PSVersion.Major -ge 7)) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-ConsoleGridView -OutputMode Multiple -Title $GridViewTitle).Name | Sort-Object -Property Name
        } elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
        } else {
            # To Do: Check for admin and prompt to install features/modules or revert to 'All'.
            Write-Information "Out-GridView and Out-ConsoleGridView were not found on your system. Defaulting to 'All'."
            $Scans = 'All'
        }
    }

    switch ( $Scans ) {
        Auditing {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
        }
        ESC1 {
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        ESC2 {
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        ESC3 {
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3C1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            [array]$ESC3 += Find-ESC3C2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        ESC4 {
            Write-Host 'Identifying AD CS templates with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        ESC5 {
            Write-Host 'Identifying AD CS objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -UnsafeUsers $UnsafeUsers
        }
        ESC6 {
            Write-Host 'Identifying Issuing CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC7 {
            Write-Host 'Identifying Issuing CAs with Non-Standard Admins (ESC7)...'
            [array]$ESC7 = Find-ESC7 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers -SafeUsers $SafeUsers
        }
        ESC8 {
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC9 {
            Write-Host 'Identifying AD CS templates with szOID_NTDS_CA_SECURITY_EXT disabled (ESC9)...'
            [array]$ESC9 = Find-ESC9 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        ESC11 {
            Write-Host 'Identifying Issuing CAs with IF_ENFORCEENCRYPTICERTREQUEST disabled (ESC11)...'
            [array]$ESC11 = Find-ESC11 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC13 {
            Write-Host 'Identifying AD CS templates with dangerous ESC13 configurations...'
            [array]$ESC13 = Find-ESC13 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEKUs -UnsafeUsers $UnsafeUsers
        }
        ESC15 {
            Write-Host 'Identifying AD CS templates with dangerous ESC15/EKUwu configurations...'
            [array]$ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        EKUwu {
            Write-Host 'Identifying AD CS templates with dangerous ESC15/EKUwu configurations...'
            [array]$ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC16 {
            Write-Host 'Identifying Issuing CAs with szOID_NTDS_CA_SECURITY_EXT disabled (ESC16)...'
            [array]$ESC16 = Find-ESC16 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC17 {
            Write-Host 'Identifying AD CS templates with dangerous ESC17 configurations...'
            [array]$ESC17 = Find-ESC17 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ServerAuthEKUs $ServerAuthEKUs -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        All {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3C1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            [array]$ESC3 += Find-ESC3C2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -Mode $Mode -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with Non-Standard Admins (ESC7)...'
            [array]$ESC7 = Find-ESC7 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers -SafeUsers $SafeUsers
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with szOID_NTDS_CA_SECURITY_EXT disabled (ESC9)...'
            [array]$ESC9 = Find-ESC9 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with IF_ENFORCEENCRYPTICERTREQUEST disabled (ESC11)...'
            [array]$ESC11 = Find-ESC11 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC13 configurations...'
            [array]$ESC13 = Find-ESC13 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC15 configurations...'
            [array]$ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with szOID_NTDS_CA_SECURITY_EXT disabled (ESC16)...'
            [array]$ESC16 = Find-ESC16 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC17 configurations...'
            [array]$ESC17 = Find-ESC17 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ServerAuthEKUs $ServerAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
    }

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC7 + $ESC8 + $ESC9 + $ESC11 + $ESC13 + $ESC15 + $ESC16 + $ESC17

    # If these are all empty = no issues found, exit
    if ($AllIssues.Count -lt 1) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found. :)" -ForegroundColor Green
        break
    }

    # Return a hash table of array names (keys) and arrays (values) so they can be directly referenced with other functions
    return @{
        AllIssues      = $AllIssues
        AuditingIssues = $AuditingIssues
        ESC1           = $ESC1
        ESC2           = $ESC2
        ESC3           = $ESC3
        ESC4           = $ESC4
        ESC5           = $ESC5
        ESC6           = $ESC6
        ESC7           = $ESC7
        ESC8           = $ESC8
        ESC9           = $ESC9
        ESC11          = $ESC11
        ESC13          = $ESC13
        ESC15          = $ESC15
        ESC16          = $ESC16
        ESC17          = $ESC17
    }
}
