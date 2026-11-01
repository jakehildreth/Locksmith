function Complete-CAStage {
    <#
    .SYNOPSIS
        Waits for one Stage of an Availability check and returns its result.

    .DESCRIPTION
        Takes the handle from Start-CADnsCheck, Start-CAIcmpCheck, Start-CATransportCheck, or
        Start-CACertutilCheck. It waits until the Stage finishes or until its timeout passes,
        counted from the moment the Stage started. It never throws for a failed Stage. It returns
        a result object and cleans up the socket, process, or job.

        Every result has Passed, ElapsedMs, and Detail. ElapsedMs is the time from the start of the
        Stage to the moment this function collected the result, so it is an upper bound when other
        Stages were collected first. The transport result also has Port. The certutil result also has
        HResult (the signed integer exit code), TimedOut, and RemoteError. RemoteError is true when
        the remote command itself failed on the -Credential path, before certutil could run.

    .PARAMETER Handle
        The handle that a Start-CA*Check function returned.

    .OUTPUTS
        PSCustomObject.

    .EXAMPLE
        Start-CATransportCheck -ComputerName 'ca1.corp.example' | Complete-CAStage
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The function only collects the result of a read-only probe and changes no system state.')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [pscustomobject]$Handle
    )

    process {
        $timeoutText = ($Handle.TimeoutMilliseconds / 1000).ToString([System.Globalization.CultureInfo]::InvariantCulture)
        $remaining = [int][Math]::Max(0, $Handle.TimeoutMilliseconds - $Handle.Stopwatch.ElapsedMilliseconds)

        $passed = $false
        $detail = $null
        $hresult = $null
        $timedOut = $false
        $remoteError = $false

        try {
            if ($Handle.StartError) {
                $detail = $Handle.StartError
            } elseif ($Handle.Kind -in 'Dns', 'Icmp', 'Transport') {
                $finished = [System.Threading.Tasks.Task]::WaitAny([System.Threading.Tasks.Task[]]@($Handle.Task), $remaining) -ne -1
                if (-not $finished) {
                    $timedOut = $true
                    $detail = "Timed out after ${timeoutText}s"
                } elseif ($Handle.Task.IsFaulted) {
                    $detail = $Handle.Task.Exception.GetBaseException().Message
                } else {
                    switch ($Handle.Kind) {
                        'Dns' {
                            $addresses = @($Handle.Task.Result)
                            $passed = $addresses.Count -gt 0
                            $detail = if ($passed) { $addresses[0].ToString() } else { 'No addresses returned' }
                        }
                        'Icmp' {
                            $reply = $Handle.Task.Result
                            $passed = $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
                            $detail = if ($passed) { "Reply in $($reply.RoundtripTime)ms" } else { $reply.Status.ToString() }
                        }
                        'Transport' {
                            $passed = $true
                            $detail = "TCP $($Handle.Port) open"
                        }
                    }
                }
            } elseif ($Handle.Process) {
                if ($Handle.Process.WaitForExit($remaining)) {
                    $Handle.Process.WaitForExit()
                    $text = ($Handle.StandardOutput.Result + "`n" + $Handle.StandardError.Result)
                    $hresult = $Handle.Process.ExitCode
                } else {
                    $timedOut = $true
                    $Handle.Process.Kill()
                    $detail = "Timed out after ${timeoutText}s"
                }
            } elseif ($Handle.Job) {
                $waitSeconds = [int][Math]::Max(1, [Math]::Ceiling($remaining / 1000))
                $null = Wait-Job -Job $Handle.Job -Timeout $waitSeconds
                switch ($Handle.Job.State) {
                    'Completed' {
                        $remote = Receive-Job -Job $Handle.Job -ErrorAction SilentlyContinue | Select-Object -Last 1
                        $text = [string]$remote.Output
                        $hresult = $remote.ExitCode
                    }
                    'Failed' {
                        $remoteError = $true
                        $reason = $Handle.Job.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason } | Where-Object { $_ } | Select-Object -First 1
                        if (-not $reason) { $reason = $Handle.Job.JobStateInfo.Reason }
                        $detail = if ($reason) { $reason.Message } else { 'The remote command failed.' }
                    }
                    default {
                        $timedOut = $true
                        $null = Stop-Job -Job $Handle.Job -ErrorAction SilentlyContinue
                        $detail = "Timed out after ${timeoutText}s"
                    }
                }
            }

            if ($Handle.Kind -eq 'Certutil' -and -not $timedOut -and -not $remoteError -and -not $Handle.StartError) {
                $lines = @($text -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^Connecting to ' })
                $detail = $lines -join ' '
                if ($null -eq $hresult -and $detail -match '0x[0-9a-fA-F]{8}') {
                    $hresult = [Convert]::ToInt32($Matches[0].Substring(2), 16)
                }
                $passed = $hresult -eq 0
                if ($passed) { $hresult = $null }
            }
        } catch {
            $detail = $_.Exception.GetBaseException().Message
        } finally {
            if ($Handle.Client) { $Handle.Client.Dispose() }
            if ($Handle.Ping) { $Handle.Ping.Dispose() }
            if ($Handle.Process) { $Handle.Process.Dispose() }
            if ($Handle.Job) { Remove-Job -Job $Handle.Job -Force -ErrorAction SilentlyContinue }
        }

        $result = [ordered]@{
            Passed    = $passed
            ElapsedMs = [int]$Handle.Stopwatch.ElapsedMilliseconds
            Detail    = $detail
        }
        if ($Handle.Kind -eq 'Transport') {
            $result.Port = $Handle.Port
        }
        if ($Handle.Kind -eq 'Certutil') {
            $result.HResult = $hresult
            $result.TimedOut = $timedOut
            $result.RemoteError = $remoteError
        }
        [pscustomobject]$result
    }
}
