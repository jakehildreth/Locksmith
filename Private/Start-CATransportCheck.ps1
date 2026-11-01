function Start-CATransportCheck {
    <#
    .SYNOPSIS
        Starts the transport Stage of an Availability check.

    .DESCRIPTION
        Starts a TCP connection to a port on the CA host and returns at once with a handle. Pass the
        handle to Complete-CAStage to wait for the result. The caller chooses the port by the path
        Locksmith uses to read the CA:
          - TCP 135, the RPC endpoint mapper, when certutil reads the CA with the current identity.
          - TCP 5985 or 5986, WinRM, when the reads use -Credential through Invoke-Command.

        Test-NetConnection and Test-Connection cannot do this job. Test-NetConnection has no timeout
        and takes about 21 seconds to fail against an unreachable host, and Test-Connection
        -TimeoutSeconds exists only in PowerShell 7.

    .PARAMETER ComputerName
        The CA host name or IP address.

    .PARAMETER Port
        The TCP port to connect to. Defaults to 135.

    .PARAMETER TimeoutMilliseconds
        How long Complete-CAStage waits, counted from the start. Defaults to 3000.

    .OUTPUTS
        PSCustomObject. A handle for Complete-CAStage.

    .EXAMPLE
        Start-CATransportCheck -ComputerName 'ca1.corp.example' | Complete-CAStage
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The function only starts a read-only probe and changes no system state.')]
    param (
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [ValidateRange(1, 65535)]
        [int]$Port = 135,

        [ValidateRange(1, 60000)]
        [int]$TimeoutMilliseconds = 3000
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $client = [System.Net.Sockets.TcpClient]::new()
    $task = $null
    $startError = $null
    try {
        $task = $client.ConnectAsync($ComputerName, $Port)
    } catch {
        $startError = $_.Exception.GetBaseException().Message
    }

    [pscustomobject]@{
        Kind                = 'Transport'
        Stopwatch           = $stopwatch
        TimeoutMilliseconds = $TimeoutMilliseconds
        Client              = $client
        Port                = $Port
        Task                = $task
        StartError          = $startError
    }
}
