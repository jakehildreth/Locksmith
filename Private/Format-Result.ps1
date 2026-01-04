function Format-Result {
    <#
    .SYNOPSIS
        Formats the result of an issue for display.

    .DESCRIPTION
        This script formats the result of an issue for display based on the specified mode.

    .PARAMETER Issue
        The issue object containing information about the detected issue.

    .PARAMETER Mode
        The mode to determine the formatting style. Valid values are 0 and 1.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 0
        Formats the issue result in table format.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 1
        Formats the issue result in list format.

    .NOTES
        Authors: Spencer Alessi & Jake Hildreth
    #>
    [CmdletBinding()]
    param(
        $Issue,
        [Parameter(Mandatory)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT        = 'Auditing Not Fully Enabled'
        ESC1          = 'ESC1 - Vulnerable Certificate Template - Client Authentication'
        ESC2          = 'ESC2 - Vulnerable Certificate Template - Subordinate CA/Any Purpose'
        ESC3          = 'ESC3 - Vulnerable Certificate Template - Enrollment Agent'
        ESC4          = 'ESC4 - Vulnerable Access Control - Certificate Template'
        ESC5          = 'ESC5 - Vulnerable Access Control - PKI Object'
        ESC6          = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled'
        ESC7          = 'ESC7 - Non-standard PKI Admins'
        ESC8          = 'ESC8 - HTTP/S Enrollment Enabled'
        ESC9          = 'ESC9 - szOID_NTDS_CA_SECURITY_EXT Extension Disabled on Template'
        ESC11         = 'ESC11 - IF_ENFORCEENCRYPTICERTREQUEST Flag Disabled'
        ESC13         = 'ESC13 - Vulnerable Certificate Template - Group-Linked'
        'ESC15/EKUwu' = 'ESC15 - Vulnerable Certificate Template - Schema V1'
        ESC16         = 'ESC16 - szOID_NTDS_CA_SECURITY_EXT Extension Disabled on CA'
        ESC17         = 'ESC17 - Vulnerable Certificate Template - Server Authentication'
    }

    $RiskTable = @{
        'Informational' = 'Black, White'
        'Low'           = 'Black, Yellow'
        'Medium'        = 'Black, DarkYellow'
        'High'          = 'Black, Red'
        'Critical'      = 'White, DarkRed'
    }

    if ($null -ne $Issue) {
        $UniqueIssue = $Issue.Technique | Sort-Object -Unique
        $Title = $($IssueTable[$UniqueIssue])
        Write-Host "$('-'*($($Title.ToString().Length + 10)))" -ForeGroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
        Write-Host "     " -BackgroundColor Magenta -NoNewline
        Write-Host $Title -BackgroundColor Magenta -ForeGroundColor Black -NoNewline
        Write-Host "     " -BackgroundColor Magenta -NoNewline; Write-Host
        Write-Host "$('-'*($($Title.ToString().Length + 10)))" -ForeGroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host


        if ($Mode -eq 0) {
            # TODO Refactor this
            switch ($UniqueIssue) {
                { $_ -in @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC16') } {
                    $Issue |
                    Format-Table Technique, @{l = 'CA Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Issue -Wrap |
                    Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                { $_ -in @('ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC9', 'ESC13', 'ESC15/EKUwu', 'ESC17') } {
                    $Issue |
                    Format-Table Technique, @{l = 'Template Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Enabled, Issue -Wrap |
                    Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                'ESC5' {
                    $Issue |
                    Format-Table Technique, @{l = 'Object Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Issue -Wrap |
                    Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
            }
        } elseif ($Mode -eq 1) {
            switch ($UniqueIssue) {
                { $_ -in @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC16') } {
                    $Issue |
                    Format-List Technique, @{l = 'CA Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, DistinguishedName, Issue, Fix, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } |
                    Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                { $_ -in @('ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC9', 'ESC13', 'ESC15/EKUwu') } {
                    $Issue |
                    Format-List Technique, @{l = 'Template Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, DistinguishedName, Enabled, EnabledOn, Issue, Fix, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } |
                    Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                'ESC5' {
                    $Issue |
                    Format-List Technique, @{l = 'Object Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, DistinguishedName, objectClass, Issue, Fix, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } |
                    Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
            }
        }
    }
}
