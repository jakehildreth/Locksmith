function Get-CAUnavailabilityReason {
    <#
    .SYNOPSIS
        Chooses the primary Unavailability reason for a CA that is not Reachable.

    .DESCRIPTION
        Reads the four Stage results of an Availability check and returns one reason. It returns
        nothing when the certutil ping passed, because the CA is Reachable.

        The first match wins:
          1. An HResult that proves the host answered (access denied, class not registered).
             The DNS and transport probes can give false negatives, so this beats them.
          2. DNS failed.
          3. The transport check failed.
          4. A remote command failed (the -Credential path).
          5. The certutil HResult from the table in Get-CAHResultReason, or a certutil timeout,
             which counts as a CA service that does not answer.

        Every Stage result is still available in the CAStageResult object. Get-CAStageSummary
        turns them into a line for the person reading the output.

    .PARAMETER StageResult
        The CAStageResult object with the members DNS, ICMP, Transport, and Certutil.

    .PARAMETER ComputerName
        The CA host name, used in the text for a person.

    .OUTPUTS
        PSCustomObject with the members Id, Text, Sentence, and Hint. Nothing when the CA is Reachable.

    .EXAMPLE
        Get-CAUnavailabilityReason -StageResult $CA.CAStageResult -ComputerName $CA.dNSHostName
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$StageResult,

        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $certutil = $StageResult.Certutil
    if ($certutil.Passed) {
        return
    }

    $port = $StageResult.Transport.Port
    $transportName = if ($port -eq 135) { 'TCP 135 (RPC endpoint mapper)' } else { "WinRM (TCP $port)" }
    $hresultReason = if ($null -ne $certutil.HResult) { Get-CAHResultReason -HResult ([int]$certutil.HResult) }

    $id = if ($hresultReason -and $hresultReason.ProvesHostAnswered) {
        $hresultReason.Id
    } elseif (-not $StageResult.DNS.Passed) {
        'HostNameNotResolved'
    } elseif (-not $StageResult.Transport.Passed) {
        'TransportUnreachable'
    } elseif ($certutil.RemoteError) {
        'RemoteCommandFailed'
    } elseif ($hresultReason) {
        $hresultReason.Id
    } elseif ($certutil.TimedOut) {
        'ServiceNotAnswering'
    } else {
        'Unrecognized'
    }

    $hresultText = if ($hresultReason) { $hresultReason.HResultText } else { $null }
    $answerDetail = if ($hresultText) { $hresultText } elseif ($certutil.TimedOut) { 'timed out' } else { $certutil.Detail }

    $reasons = @{
        HostNameNotResolved  = @{
            Text     = 'Host name not resolved'
            Sentence = "Cannot resolve the CA host name $ComputerName in DNS."
            Hint     = "Check the dNSHostName on the CA's pKIEnrollmentService object and the DNS records for $ComputerName."
        }
        TransportUnreachable = @{
            Text     = 'Host not reachable on the transport port'
            Sentence = "Cannot connect to $ComputerName on $transportName."
            Hint     = if ($port -eq 135) {
                "Check that $ComputerName is online and that a firewall allows TCP 135 and the dynamic RPC range 49152-65535 from this machine."
            } else {
                "Check that $ComputerName is online and that WinRM is enabled and allowed through the firewall."
            }
        }
        ServiceNotAnswering  = @{
            Text     = 'CA service not answering'
            Sentence = "The host responds, but the CA service did not answer ($answerDetail)."
            Hint     = "Check that the 'certsvc' service is running on $ComputerName."
        }
        CANotFound           = @{
            Text     = 'CA not found at that name'
            Sentence = "The host responds, but no CA with this name was found ($hresultText)."
            Hint     = "Check that the CA is installed on $ComputerName and that its name matches its pKIEnrollmentService object."
        }
        AccessDenied         = @{
            Text     = 'Access denied'
            Sentence = "$ComputerName answered, but denied access ($hresultText). This account cannot read the CA's configuration."
            Hint     = 'Run Locksmith as a CA Administrator, or supply -Credential.'
        }
        RemoteCommandFailed  = @{
            Text     = 'Remote command failed'
            Sentence = "The remote command on $ComputerName failed: $($certutil.Detail)"
            Hint     = "Check that WinRM is enabled on $ComputerName and that the credential is valid there."
        }
        Unrecognized         = @{
            Text     = 'Unrecognized failure'
            Sentence = "certutil failed with an unrecognized error ($(if ($hresultText) { $hresultText } else { 'no HResult' })): $($certutil.Detail)"
            Hint     = "Run 'certutil -config <CA> -pingadmin' from this machine and check the error."
        }
    }

    [pscustomobject]@{
        Id       = $id
        Text     = $reasons[$id].Text
        Sentence = $reasons[$id].Sentence
        Hint     = $reasons[$id].Hint
    }
}
