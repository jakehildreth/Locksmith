function Invoke-CertutilGetReg {
    <#
    .SYNOPSIS
        Reads one registry value from a Certificate Authority with certutil -getreg.

    .DESCRIPTION
        Runs 'certutil -config <CA> -getreg <Path>' and returns the exit code and the output lines.
        It never throws for a failed read. The caller decides what a failure means.

        Without a credential, certutil runs here. With a credential, certutil runs on the CA host
        through Invoke-Command (WinRM) and the exit code comes back with the output. The exit code
        is the HRESULT of the failure, and Locksmith matches on that number, not on the text.

        The read has no timeout. The Availability check runs first, and Locksmith reads only CAs
        that answered it.

    .PARAMETER CAFullName
        The CA configuration string, in the form 'host\CA name'.

    .PARAMETER ComputerName
        The CA host name. Used only with -Credential.

    .PARAMETER Credential
        When given, certutil runs on the CA host through WinRM with this credential.

    .PARAMETER Path
        The registry path under the CA configuration, for example 'CA\AuditFilter'.

    .OUTPUTS
        PSCustomObject with the members Passed, HResult, Output, Detail, and RemoteError.
        HResult is null when the read passed. RemoteError is true when the remote command itself
        failed before certutil ran.

    .EXAMPLE
        Invoke-CertutilGetReg -CAFullName 'ca1.corp.example\Corp CA' -ComputerName 'ca1.corp.example' -Path 'CA\AuditFilter'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [string]$CAFullName,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $exitCode = $null
    $output = @()
    $remoteError = $false
    $failureDetail = $null

    try {
        if ($Credential) {
            $remote = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                $lines = certutil -config $using:CAFullName -getreg $using:Path 2>&1 | ForEach-Object { "$_" }
                [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = @($lines) }
            }
            $exitCode = $remote.ExitCode
            $output = [string[]]@($remote.Output)
        } else {
            $output = [string[]]@(certutil -config $CAFullName -getreg $Path 2>&1 | ForEach-Object { "$_" })
            $exitCode = $LASTEXITCODE
        }
    } catch {
        $remoteError = [bool]$Credential
        $failureDetail = $_.Exception.GetBaseException().Message
    }

    $text = ($output | Where-Object { $_.Trim() }) -join ' '
    if ($null -eq $exitCode -and -not $failureDetail -and $text -match '0x[0-9a-fA-F]{8}') {
        $exitCode = [Convert]::ToInt32($Matches[0].Substring(2), 16)
    }

    $passed = (-not $failureDetail) -and ($exitCode -eq 0)

    [pscustomobject]@{
        Passed      = $passed
        HResult     = if ($passed -or $remoteError) { $null } else { $exitCode }
        Output      = $output
        Detail      = if ($failureDetail) { $failureDetail } else { $text }
        RemoteError = $remoteError
    }
}
