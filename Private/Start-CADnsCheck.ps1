function Start-CADnsCheck {
    <#
    .SYNOPSIS
        Starts the DNS Stage of an Availability check.

    .DESCRIPTION
        Starts resolving the CA host name and returns at once with a handle. Pass the handle to
        Complete-CAStage to wait for the result. Starting every Stage first and completing them
        after lets the four Stages of one CA run at the same time, without runspaces, on both
        Windows PowerShell 5.1 and PowerShell 7.

    .PARAMETER ComputerName
        The CA host name to resolve.

    .PARAMETER TimeoutMilliseconds
        How long Complete-CAStage waits, counted from the start. Defaults to 3000.

    .OUTPUTS
        PSCustomObject. A handle for Complete-CAStage.

    .EXAMPLE
        Start-CADnsCheck -ComputerName 'ca1.corp.example' | Complete-CAStage
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The function only starts a read-only probe and changes no system state.')]
    param (
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [ValidateRange(1, 60000)]
        [int]$TimeoutMilliseconds = 3000
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $task = $null
    $startError = $null
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($ComputerName)
    } catch {
        $startError = $_.Exception.GetBaseException().Message
    }

    [pscustomobject]@{
        Kind                = 'Dns'
        Stopwatch           = $stopwatch
        TimeoutMilliseconds = $TimeoutMilliseconds
        Task                = $task
        StartError          = $startError
    }
}
