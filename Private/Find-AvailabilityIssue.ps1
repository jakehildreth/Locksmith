function Find-AvailabilityIssue {
    <#
    .SYNOPSIS
        Finds Certificate Authorities that Locksmith could not fully read.

    .DESCRIPTION
        Returns one AVAILABILITY row for each CA that is not Reachable, or that is Reachable but had
        one or more reads fail. The row replaces the placeholder rows that DETECT, ESC6, ESC11, and
        ESC16 used to give for an unavailable CA, and it explains why the CA could not be read.

        The Issue text has three parts:
          1. The cause, in plain words. For a Reachable CA with failed reads it lists each failure.
          2. The techniques that were not evaluated.
          3. The result of each Stage of the Availability check.

        Fix is a one-line hint for a person. It is not a script. AVAILABILITY rows must never go to
        Invoke-Remediation or Export-RevertScript. Revert is always 'N/A'.

        A CA object that never went through Set-AdditionalCAProperty has no Reachable property and
        is ignored.

    .PARAMETER ADCSObjects
        The AD CS objects, after Set-AdditionalCAProperty added the availability properties.

    .PARAMETER SafeUsers
        A regular expression of safe SIDs. Passed to Set-RiskRating.

    .PARAMETER UnsafeUsers
        A regular expression of unsafe SIDs. Passed to Set-RiskRating.

    .PARAMETER SkipRisk
        Do not rate the rows.

    .OUTPUTS
        PSCustomObject, one for each CA with a problem.

    .EXAMPLE
        Find-AvailabilityIssue -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )

    # The technique that depends on each value, in the order Locksmith reports them.
    $TechniqueOrder = @('DETECT', 'ESC6', 'ESC7', 'ESC11', 'ESC16')
    $TechniqueByProperty = @{
        AuditFilter          = 'DETECT'
        SANFlag              = 'ESC6'
        CAAdministrator      = 'ESC7'
        CertificateManager   = 'ESC7'
        InterfaceFlag        = 'ESC11'
        DisableExtensionList = 'ESC16'
    }

    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKIEnrollmentService') -and
        ($null -ne $_.Reachable) -and
        ((-not $_.Reachable) -or ($_.CAReadFailure.Count -gt 0))
    } | ForEach-Object {
        $CAFullName = if ($_.CAFullName) { $_.CAFullName } else { "$($_.dNSHostName)\$($_.Name)" }
        $StageSummary = Get-CAStageSummary -StageResult $_.CAStageResult

        if (-not $_.Reachable) {
            $Cause = $_.CAUnavailabilityReason.Sentence
            $Fix = $_.CAUnavailabilityReason.Hint
            $NotEvaluated = $TechniqueOrder
        } else {
            $Failures = $_.CAReadFailure
            $FailureText = @($Failures.Keys | Group-Object { $Failures[$_] } | Sort-Object { ($_.Group | ForEach-Object { $TechniqueOrder.IndexOf($TechniqueByProperty[$_]) } | Measure-Object -Minimum).Minimum } | ForEach-Object {
                    "$((@($_.Group) | Sort-Object { $TechniqueOrder.IndexOf($TechniqueByProperty[$_]) }, { $_ }) -join ', ') ($($_.Name))"
                }) -join '; '
            $Cause = "Partly evaluated. Could not read: $FailureText."
            $NotEvaluated = $TechniqueOrder | Where-Object { $_ -in @($Failures.Keys | ForEach-Object { $TechniqueByProperty[$_] }) }
            $AllFailureText = @($Failures.Values) -join ' '
            $Fix = if ($AllFailureText -match 'Access denied') {
                'Run Locksmith as a CA Administrator, or supply -Credential.'
            } elseif ($AllFailureText -match 'Remote command failed') {
                "Check that WinRM is enabled on $($_.dNSHostName) and that the credential is valid there."
            } else {
                "Run certutil -config '$CAFullName' -getreg for the settings that failed, from this machine, and check the errors."
            }
        }

        $Issue = [pscustomobject]@{
            Forest            = $_.CanonicalName.split('/')[0]
            Name              = $_.Name
            CAFullName        = $CAFullName
            DistinguishedName = $_.DistinguishedName
            Technique         = 'AVAILABILITY'
            Issue             = "$Cause Not evaluated: $($NotEvaluated -join ', '). Stages: $StageSummary."
            Fix               = $Fix
            Revert            = 'N/A'
        }
        if ($SkipRisk -eq $false) {
            Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        $Issue
    }
}
