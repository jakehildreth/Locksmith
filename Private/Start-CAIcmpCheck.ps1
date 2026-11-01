function Start-CAIcmpCheck {
    <#
    .SYNOPSIS
        Starts the ICMP Stage of an Availability check.

    .DESCRIPTION
        Starts one ICMP echo to the CA host and returns at once with a handle. Pass the handle to
        Complete-CAStage to wait for the result.

        A failed ICMP Stage never makes a CA unavailable. Many hosts block ICMP echo, and Windows
        Firewall does so by default. Locksmith records the result as supporting detail only.

    .PARAMETER ComputerName
        The CA host name or IP address to ping.

    .PARAMETER TimeoutMilliseconds
        How long Complete-CAStage waits, counted from the start. Defaults to 2000.

    .OUTPUTS
        PSCustomObject. A handle for Complete-CAStage.

    .EXAMPLE
        Start-CAIcmpCheck -ComputerName 'ca1.corp.example' | Complete-CAStage
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The function only starts a read-only probe and changes no system state.')]
    param (
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [ValidateRange(1, 60000)]
        [int]$TimeoutMilliseconds = 2000
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $ping = [System.Net.NetworkInformation.Ping]::new()
    $task = $null
    $startError = $null
    try {
        $task = $ping.SendPingAsync($ComputerName, $TimeoutMilliseconds)
    } catch {
        $startError = $_.Exception.GetBaseException().Message
    }

    [pscustomobject]@{
        Kind                = 'Icmp'
        Stopwatch           = $stopwatch
        TimeoutMilliseconds = $TimeoutMilliseconds
        Ping                = $ping
        Task                = $task
        StartError          = $startError
    }
}
