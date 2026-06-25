function Invoke-Remediation {
    <#
    .SYNOPSIS
    Runs any remediation scripts available.

    .DESCRIPTION
    This function offers to run any remediation code associated with identified issues.

    .PARAMETER AuditingIssues
    A PS Object containing all necessary information about auditing issues.

    .PARAMETER ESC1
    A PS Object containing all necessary information about ESC1 issues.

    .PARAMETER ESC2
    A PS Object containing all necessary information about ESC2 issues.

    .PARAMETER ESC3
    A PS Object containing all necessary information about ESC3 issues.

    .PARAMETER ESC4
    A PS Object containing all necessary information about ESC4 issues.

    .PARAMETER ESC5
    A PS Object containing all necessary information about ESC5 issues.

    .PARAMETER ESC6
    A PS Object containing all necessary information about ESC6 issues.

    .PARAMETER ESC11
    A PS Object containing all necessary information about ESC11 issues.

    .PARAMETER ESC13
    A PS Object containing all necessary information about ESC13 issues.

    .INPUTS
    PS Objects

    .OUTPUTS
    Console output
    #>

    [CmdletBinding()]
    param (
        $AuditingIssues,
        $ESC1,
        $ESC2,
        $ESC3,
        $ESC4,
        $ESC5,
        $ESC6,
        $ESC11,
        $ESC13
    )

    Write-Host "`nExecuting Mode 4 - Attempting to fix identified issues!`n" -ForegroundColor Green
    Write-Host 'Creating a script (' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1' -ForegroundColor White -NoNewline
    Write-Host ") which can be used to revert all changes made by Locksmith...`n"
    try {
        $params = @{
            AuditingIssues = $AuditingIssues
            ESC1           = $ESC1
            ESC2           = $ESC2
            ESC3           = $ESC3
            ESC4           = $ESC4
            ESC5           = $ESC5
            ESC6           = $ESC6
            ESC11          = $ESC11
            ESC13          = $ESC13
        }
        Export-RevertScript @params
    } catch {
        Write-Warning 'Creation of Invoke-RevertLocksmith.ps1 failed.'
        Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
        Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
        Write-Host 'No: ' -NoNewline
        $WarningError = ''
        $WarningError = Read-Host
        if ($WarningError -like 'y') {
            # Continue
        } else {
            break
        }
    }
    if ($AuditingIssues) {
        $AuditingIssues | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to fully enable auditing on Certification Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not modify AD CS auditing. Are you a local admin on the CA host?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC1) {
        $ESC1 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'COMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }

        }
    }
    if ($ESC2) {
        $ESC2 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC4) {
        $ESC4 | Where-Object Issue -Like '* Owner rights *' | ForEach-Object { # This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" template to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC5) {
        $ESC5 | Where-Object Issue -Like '* Owner rights *' | ForEach-Object { # TODO This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" object to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC6) {
        $ESC6 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the Certificate Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            $WarningError = 'n'
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Are you an Active Directory or AD CS admin?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    if ($ESC11) {
        $ESC11 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable the IF_ENFORCEENCRYPTICERTREQUEST flag on the Certificate Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            $WarningError = 'n'
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not enable the IF_ENFORCEENCRYPTICERTREQUEST flag. Are you an Active Directory or AD CS admin?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    if ($ESC13) {
        $ESC13 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'COMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                } catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            } else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "Mode 4 Complete! There are no more issues that Locksmith can automatically resolve.`n" -ForegroundColor Green
    Write-Host 'If you experience any operational impact from using Locksmith Mode 4, use ' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1 ' -ForegroundColor White
    Write-Host "to revert all changes made by Locksmith. It can be found in the current working directory.`n"
    Write-Host @"
[!] Locksmith cannot automatically resolve all AD CS issues at this time.
There may be more AD CS issues remaining in your environment.
Use Locksmith in Modes 0-3 to further investigate your environment
or reach out to the Locksmith team for assistance. We'd love to help!`n
"@ -ForegroundColor Yellow
}
