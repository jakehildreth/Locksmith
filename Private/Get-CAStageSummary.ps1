function Get-CAStageSummary {
    <#
    .SYNOPSIS
        Builds the one-line summary of an Availability check.

    .DESCRIPTION
        Turns the four Stage results of an Availability check into one line, for example
        'DNS ok, ICMP failed, TCP 135 ok, certutil 0x800706ba'. Locksmith puts this line in the
        Issue text of an AVAILABILITY row so the Stage detail survives the table and CSV output.

    .PARAMETER StageResult
        The CAStageResult object with the members DNS, ICMP, Transport, and Certutil.

    .OUTPUTS
        String.

    .EXAMPLE
        Get-CAStageSummary -StageResult $CA.CAStageResult
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$StageResult
    )

    $outcome = { param($Stage) if ($Stage.Passed) { 'ok' } else { 'failed' } }

    $transportPort = $StageResult.Transport.Port
    $transportLabel = if ($transportPort -eq 135) { 'TCP 135' } else { "WinRM $transportPort" }

    $certutil = $StageResult.Certutil
    $certutilOutcome = if ($certutil.Passed) {
        'ok'
    } elseif ($certutil.TimedOut) {
        'timed out'
    } elseif ($certutil.RemoteError) {
        'remote error'
    } elseif ($null -ne $certutil.HResult) {
        '0x{0:x8}' -f [int]$certutil.HResult
    } else {
        'failed'
    }

    "DNS $(& $outcome $StageResult.DNS), ICMP $(& $outcome $StageResult.ICMP), $transportLabel $(& $outcome $StageResult.Transport), certutil $certutilOutcome"
}
