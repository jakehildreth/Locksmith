function Test-CATransport {
    <#
    .SYNOPSIS
        Tests whether a TCP port on a Certificate Authority host accepts connections, with a hard timeout.

    .DESCRIPTION
        Opens a TCP connection to the given host and port and waits no longer than the timeout.
        Locksmith uses it to check the RPC endpoint mapper (TCP 135), the transport that certutil uses
        to read a CA's configuration. Test-NetConnection and Test-Connection cannot be used for this:
        Test-NetConnection has no timeout and takes about 21 seconds to fail against an unreachable host,
        and Test-Connection -TimeoutSeconds exists only in PowerShell 7.

        The function never throws for a failed connection. It returns a result object that says
        whether the port was open and why not when it was not.

    .PARAMETER ComputerName
        The host name or IP address to connect to.

    .PARAMETER Port
        The TCP port to connect to. Defaults to 135, the RPC endpoint mapper.

    .PARAMETER TimeoutMilliseconds
        How long to wait for the connection. Defaults to 3000.

    .OUTPUTS
        PSCustomObject with the members Passed (bool), ElapsedMs (int), Detail (string), and Port (int).

    .EXAMPLE
        Test-CATransport -ComputerName 'ca1.corp.example'

        Tests TCP 135 on ca1.corp.example and waits up to 3 seconds.

    .NOTES
        Works on Windows PowerShell 5.1 and PowerShell 7.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
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
    $passed = $false

    try {
        $connectTask = $client.ConnectAsync($ComputerName, $Port)
        $finishedIndex = [System.Threading.Tasks.Task]::WaitAny([System.Threading.Tasks.Task[]]@($connectTask), $TimeoutMilliseconds)

        if ($finishedIndex -eq -1) {
            $detail = "Timed out after $($TimeoutMilliseconds / 1000)s"
        } elseif ($connectTask.IsFaulted) {
            $detail = $connectTask.Exception.GetBaseException().Message
        } else {
            $passed = $true
            $detail = "TCP $Port open"
        }
    } catch {
        $detail = $_.Exception.GetBaseException().Message
    } finally {
        $client.Dispose()
        $stopwatch.Stop()
    }

    [pscustomobject]@{
        Passed    = $passed
        ElapsedMs = [int]$stopwatch.ElapsedMilliseconds
        Detail    = $detail
        Port      = $Port
    }
}
