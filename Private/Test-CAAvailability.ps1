function Test-CAAvailability {
    <#
    .SYNOPSIS
        Runs the Availability check against one Certificate Authority.

    .DESCRIPTION
        Starts four Stages at the same time and then collects each result against its own timeout:
          - DNS resolution of the CA host (3 seconds)
          - ICMP echo (2 seconds)
          - A transport check (3 seconds): TCP 135, the RPC endpoint mapper, when certutil reads the CA
            with the current identity, or WinRM on TCP 5985 and 5986 when -Credential is given
          - certutil -pingadmin (10 seconds)

        Every Stage runs and every result is recorded. Only the certutil ping decides whether the CA
        is Reachable. The other Stages explain a failure. An offline CA therefore costs at most about
        10 seconds, the timeout of the slowest Stage.

        With -Credential, the transport Stage tests both WinRM ports at once and reports the first
        that passes, or the result for 5985 when both fail.

    .PARAMETER CAFullName
        The CA configuration string, in the form 'host\CA name'.

    .PARAMETER ComputerName
        The CA host name.

    .PARAMETER Credential
        When given, the reads use WinRM through Invoke-Command with this credential.

    .OUTPUTS
        PSCustomObject with the members Reachable, CAStageResult, and CAUnavailabilityReason.
        CAUnavailabilityReason is null when the CA is Reachable.

    .EXAMPLE
        Test-CAAvailability -CAFullName 'ca1.corp.example\Corp CA' -ComputerName 'ca1.corp.example'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [string]$CAFullName,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [PSCredential]$Credential
    )

    $dnsHandle = Start-CADnsCheck -ComputerName $ComputerName -TimeoutMilliseconds 3000
    $icmpHandle = Start-CAIcmpCheck -ComputerName $ComputerName -TimeoutMilliseconds 2000
    $transportPorts = if ($Credential) { 5985, 5986 } else { 135 }
    $transportHandles = foreach ($port in $transportPorts) {
        Start-CATransportCheck -ComputerName $ComputerName -Port $port -TimeoutMilliseconds 3000
    }
    $certutilParameters = @{
        CAFullName          = $CAFullName
        ComputerName        = $ComputerName
        TimeoutMilliseconds = 10000
    }
    if ($Credential) {
        $certutilParameters.Credential = $Credential
    }
    $certutilHandle = Start-CACertutilCheck @certutilParameters

    $dnsResult = Complete-CAStage -Handle $dnsHandle
    $icmpResult = Complete-CAStage -Handle $icmpHandle
    $transportResults = @($transportHandles | ForEach-Object { Complete-CAStage -Handle $_ })
    $transportResult = $transportResults | Where-Object { $_.Passed } | Select-Object -First 1
    if (-not $transportResult) {
        $transportResult = $transportResults[0]
    }
    $certutilResult = Complete-CAStage -Handle $certutilHandle

    $stageResult = [pscustomobject]@{
        DNS       = $dnsResult
        ICMP      = $icmpResult
        Transport = $transportResult
        Certutil  = $certutilResult
    }

    [pscustomobject]@{
        Reachable              = [bool]$certutilResult.Passed
        CAStageResult          = $stageResult
        CAUnavailabilityReason = Get-CAUnavailabilityReason -StageResult $stageResult -ComputerName $ComputerName
    }
}
