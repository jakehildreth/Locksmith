[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

BeforeAll {
    . $PSScriptRoot/../Private/Get-CAHResultReason.ps1
    . $PSScriptRoot/../Private/Get-CAUnavailabilityReason.ps1
    . $PSScriptRoot/../Private/Get-CAStageSummary.ps1

    function New-StageResult {
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The helper only builds a test object.')]
        param(
            [bool]$Dns = $true,
            [bool]$Icmp = $true,
            [bool]$Transport = $true,
            [int]$Port = 135,
            [bool]$Certutil = $true,
            $HResult = $null,
            [bool]$TimedOut = $false,
            [bool]$RemoteError = $false
        )
        [pscustomobject]@{
            DNS       = [pscustomobject]@{ Passed = $Dns; ElapsedMs = 5; Detail = 'x' }
            ICMP      = [pscustomobject]@{ Passed = $Icmp; ElapsedMs = 5; Detail = 'x' }
            Transport = [pscustomobject]@{ Passed = $Transport; ElapsedMs = 5; Detail = 'x'; Port = $Port }
            Certutil  = [pscustomobject]@{ Passed = $Certutil; ElapsedMs = 5; Detail = 'certutil said this'; HResult = $HResult; TimedOut = $TimedOut; RemoteError = $RemoteError }
        }
    }
}

Describe 'Get-CAStageSummary' {
    It 'Should list every Stage with its outcome' {
        $stages = New-StageResult -Icmp $false -Certutil $false -HResult 0x800706ba
        Get-CAStageSummary -StageResult $stages | Should -Be 'DNS ok, ICMP failed, TCP 135 ok, certutil 0x800706ba'
    }

    It 'Should say certutil ok when the ping passed' {
        Get-CAStageSummary -StageResult (New-StageResult) | Should -Be 'DNS ok, ICMP ok, TCP 135 ok, certutil ok'
    }

    It 'Should label the credential path transport as WinRM' {
        $stages = New-StageResult -Port 5985 -Transport $false -Certutil $false -TimedOut $true
        Get-CAStageSummary -StageResult $stages | Should -Be 'DNS ok, ICMP ok, WinRM 5985 failed, certutil timed out'
    }

    It 'Should flag a remote command error' {
        $stages = New-StageResult -Port 5985 -Certutil $false -RemoteError $true
        Get-CAStageSummary -StageResult $stages | Should -Be 'DNS ok, ICMP ok, WinRM 5985 ok, certutil remote error'
    }
}

Describe 'Get-CAUnavailabilityReason' {
    Context 'When the certutil ping passed' {
        It 'Should return no reason, even if other Stages failed' {
            $stages = New-StageResult -Dns $false -Icmp $false -Transport $false
            Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example' | Should -BeNullOrEmpty
        }
    }

    Context 'When the Stages fail in order' {
        It 'Should blame DNS first' {
            $stages = New-StageResult -Dns $false -Icmp $false -Transport $false -Certutil $false -HResult 0x80070035
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Id | Should -Be 'HostNameNotResolved'
        }

        It 'Should blame the transport next' {
            $stages = New-StageResult -Transport $false -Certutil $false -HResult 0x800706ba
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Id | Should -Be 'TransportUnreachable'
        }

        It 'Should use the certutil HResult when DNS and the transport passed' {
            $stages = New-StageResult -Certutil $false -HResult 0x800706ba
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Id | Should -Be 'ServiceNotAnswering'
        }

        It 'Should treat a certutil timeout as a CA service that does not answer' {
            $stages = New-StageResult -Certutil $false -TimedOut $true
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Id | Should -Be 'ServiceNotAnswering'
        }

        It 'Should report a failed remote command' {
            $stages = New-StageResult -Port 5985 -Certutil $false -RemoteError $true
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Id | Should -Be 'RemoteCommandFailed'
        }

        It 'Should report an unrecognized failure when certutil gave no HResult' {
            $stages = New-StageResult -Certutil $false
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Id | Should -Be 'Unrecognized'
        }
    }

    Context 'When the HResult proves the host answered' {
        It 'Should let access denied override a failed DNS Stage' {
            $stages = New-StageResult -Dns $false -Certutil $false -HResult 0x80070005
            (Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example').Id | Should -Be 'AccessDenied'
        }

        It 'Should let access denied override a failed transport Stage' {
            $stages = New-StageResult -Transport $false -Certutil $false -HResult 0x80070005
            (Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example').Id | Should -Be 'AccessDenied'
        }

        It 'Should let class not registered override a failed transport Stage' {
            $stages = New-StageResult -Transport $false -Certutil $false -HResult 0x80040154
            (Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example').Id | Should -Be 'CANotFound'
        }

        It 'Should not let an HResult that proves nothing override a failed Stage' {
            $stages = New-StageResult -Transport $false -Certutil $false -HResult 0x80070035
            (Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example').Id | Should -Be 'TransportUnreachable'
        }
    }

    Context 'When building the text for a person' {
        It 'Should name the host and avoid the word reachable in the sentence' {
            $stages = New-StageResult -Certutil $false -HResult 0x800706ba
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Sentence | Should -Be 'The host responds, but the CA service did not answer (0x800706ba).'
            $reason.Sentence | Should -Not -Match 'reachable'
        }

        It 'Should describe a DNS failure with the host name' {
            $stages = New-StageResult -Dns $false -Certutil $false -HResult 0x80070035
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Sentence | Should -Be 'Cannot resolve the CA host name ca1.corp.example in DNS.'
        }

        It 'Should describe a blocked RPC port' {
            $stages = New-StageResult -Transport $false -Certutil $false -HResult 0x800706ba
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Sentence | Should -Be 'Cannot connect to ca1.corp.example on TCP 135 (RPC endpoint mapper).'
        }

        It 'Should describe a blocked WinRM port' {
            $stages = New-StageResult -Port 5985 -Transport $false -Certutil $false -RemoteError $true
            $reason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
            $reason.Sentence | Should -Be 'Cannot connect to ca1.corp.example on WinRM (TCP 5985).'
        }

        It 'Should give a one-line hint for <Id>' -ForEach @(
            @{ Id = 'HostNameNotResolved'; Params = @{ Dns = $false; Certutil = $false; HResult = 0x80070035 } }
            @{ Id = 'TransportUnreachable'; Params = @{ Transport = $false; Certutil = $false; HResult = 0x800706ba } }
            @{ Id = 'ServiceNotAnswering'; Params = @{ Certutil = $false; HResult = 0x800706ba } }
            @{ Id = 'CANotFound'; Params = @{ Certutil = $false; HResult = 0x80070002 } }
            @{ Id = 'AccessDenied'; Params = @{ Certutil = $false; HResult = 0x80070005 } }
            @{ Id = 'RemoteCommandFailed'; Params = @{ Port = 5985; Certutil = $false; RemoteError = $true } }
            @{ Id = 'Unrecognized'; Params = @{ Certutil = $false; HResult = 0x12345678 } }
        ) {
            $reason = Get-CAUnavailabilityReason -StageResult (New-StageResult @Params) -ComputerName 'ca1.corp.example'
            $reason.Id | Should -Be $Id
            $reason.Hint | Should -Not -BeNullOrEmpty
            $reason.Hint | Should -Not -Match "`n"
        }
    }
}
