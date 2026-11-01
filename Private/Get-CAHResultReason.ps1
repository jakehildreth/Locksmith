function Get-CAHResultReason {
    <#
    .SYNOPSIS
        Maps a certutil HRESULT to an Unavailability reason.

    .DESCRIPTION
        certutil returns the HRESULT of a failure as its exit code. Locksmith matches on this number
        and never on the message text, because the text changes on localized Windows installs.
        One table covers every certutil verb, because different verbs return different codes for the
        same cause. For example, -pingadmin returns 0x800706ba and -getreg returns 0x80070035 when a
        host name does not resolve.

        ProvesHostAnswered is true for codes that can only come from a host that received the request.
        Locksmith uses it to let such a code override a failed DNS or transport Stage.

    .PARAMETER HResult
        The HRESULT as a signed 32-bit integer, which is how certutil returns it as an exit code.

    .OUTPUTS
        PSCustomObject with the members Id, Text, HResultText, and ProvesHostAnswered.

    .EXAMPLE
        Get-CAHResultReason -HResult 0x80070005

        Returns the AccessDenied reason with the text 'Access denied (0x80070005)'.

    .NOTES
        The WinINet codes 0x80072efd and 0x80072ee7 are not in the table. They are HTTP codes,
        and Locksmith reads CAs over RPC.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [int]$HResult
    )

    $table = @{
        ([int]0x800706ba) = @{ Id = 'ServiceNotAnswering'; Name = 'CA service not answering'; ProvesHostAnswered = $false }
        ([int]0x80040154) = @{ Id = 'CANotFound'; Name = 'CA not found at that name'; ProvesHostAnswered = $true }
        ([int]0x80070002) = @{ Id = 'CANotFound'; Name = 'CA not found at that name'; ProvesHostAnswered = $false }
        ([int]0x80070043) = @{ Id = 'CANotFound'; Name = 'CA not found at that name'; ProvesHostAnswered = $false }
        ([int]0x80070035) = @{ Id = 'CANotFound'; Name = 'CA not found at that name'; ProvesHostAnswered = $false }
        ([int]0x80070005) = @{ Id = 'AccessDenied'; Name = 'Access denied'; ProvesHostAnswered = $true }
    }

    $hresultText = '0x{0:x8}' -f $HResult
    $entry = $table[$HResult]
    if (-not $entry) {
        $entry = @{ Id = 'Unrecognized'; Name = 'Unrecognized failure'; ProvesHostAnswered = $false }
    }

    [pscustomobject]@{
        Id                 = $entry.Id
        Text               = "$($entry.Name) ($hresultText)"
        HResultText        = $hresultText
        ProvesHostAnswered = $entry.ProvesHostAnswered
    }
}
