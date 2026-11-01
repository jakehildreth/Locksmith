function Start-CACertutilCheck {
    <#
    .SYNOPSIS
        Starts the certutil ping Stage of an Availability check.

    .DESCRIPTION
        Starts 'certutil -config <CA> -pingadmin' and returns at once with a handle. Pass the handle
        to Complete-CAStage to wait for the result. This Stage decides whether a CA is Reachable.
        It tests the Admin interface, which is the interface every certutil -getreg read uses.

        Without a credential, certutil runs here as a process that Complete-CAStage ends at the
        timeout. With a credential, certutil runs on the CA host through Invoke-Command -AsJob,
        because Invoke-Command has no timeout of its own, and Complete-CAStage stops the job at
        the timeout.

    .PARAMETER CAFullName
        The CA configuration string, in the form 'host\CA name'.

    .PARAMETER ComputerName
        The CA host name. Used only with -Credential.

    .PARAMETER Credential
        When given, certutil runs on the CA host through WinRM with this credential.

    .PARAMETER TimeoutMilliseconds
        How long Complete-CAStage waits, counted from the start. Defaults to 10000.

    .OUTPUTS
        PSCustomObject. A handle for Complete-CAStage.

    .EXAMPLE
        Start-CACertutilCheck -CAFullName 'ca1.corp.example\Corp CA' -ComputerName 'ca1.corp.example' | Complete-CAStage
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The function only starts a read-only probe and changes no system state.')]
    param (
        [Parameter(Mandatory)]
        [string]$CAFullName,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [PSCredential]$Credential,

        [ValidateRange(1, 120000)]
        [int]$TimeoutMilliseconds = 10000
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = $null
    $job = $null
    $standardOutput = $null
    $standardError = $null
    $startError = $null

    try {
        if ($Credential) {
            $job = Invoke-Command -ComputerName $ComputerName -Credential $Credential -AsJob -ScriptBlock {
                $output = certutil -config $using:CAFullName -pingadmin 2>&1 | Out-String
                [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
            }
        } else {
            $startInfo = [System.Diagnostics.ProcessStartInfo]::new('certutil.exe')
            $startInfo.Arguments = "-config `"$CAFullName`" -pingadmin"
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $process = [System.Diagnostics.Process]::Start($startInfo)
            $standardOutput = $process.StandardOutput.ReadToEndAsync()
            $standardError = $process.StandardError.ReadToEndAsync()
        }
    } catch {
        $startError = $_.Exception.GetBaseException().Message
    }

    [pscustomobject]@{
        Kind                = 'Certutil'
        Stopwatch           = $stopwatch
        TimeoutMilliseconds = $TimeoutMilliseconds
        Process             = $process
        StandardOutput      = $standardOutput
        StandardError       = $standardError
        Job                 = $job
        StartError          = $startError
    }
}
