[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

# Opt-in integration test. It runs only when you name a lab CA, and it never runs in CI.
#
#   $env:LOCKSMITH_TEST_CA = 'ca1.corp.example\Corp CA'     # a CA you can read with certutil -getreg
#   $env:LOCKSMITH_TEST_ABSENT_REG = 'policy\SomeValue'     # optional: a value you know is not set on that CA
#   Invoke-Pester -Path .\Tests\Test-CAAvailability.Integration.Tests.ps1
#
# The unit tests mock the network and certutil. This test checks the assumptions the mocks make:
# the HResults that certutil returns, and the behavior of the Stage functions against a real CA.

BeforeDiscovery {
    $labCA = $env:LOCKSMITH_TEST_CA
    $absentRegistryPath = $env:LOCKSMITH_TEST_ABSENT_REG
}

BeforeAll {
    foreach ($name in 'Get-CAHResultReason', 'Get-CAUnavailabilityReason', 'Get-CAStageSummary', 'Start-CADnsCheck', 'Start-CAIcmpCheck',
        'Start-CATransportCheck', 'Start-CACertutilCheck', 'Complete-CAStage', 'Test-CAAvailability', 'Invoke-CertutilGetReg') {
        . "$PSScriptRoot/../Private/$name.ps1"
    }
    $labCA = $env:LOCKSMITH_TEST_CA
    if ($labCA) {
        $labHost = $labCA.Split('\')[0]
        $labName = $labCA.Substring($labHost.Length + 1)
    }
    $reasonIds = 'HostNameNotResolved', 'TransportUnreachable', 'ServiceNotAnswering', 'CANotFound', 'AccessDenied', 'RemoteCommandFailed', 'Unrecognized'
}

Describe 'Availability check against a real CA' -Tag 'Integration' -Skip:(-not $labCA) {
    Context 'When the CA is the lab CA' {
        BeforeAll {
            $result = Test-CAAvailability -CAFullName $labCA -ComputerName $labHost
        }

        It 'Should be Reachable' {
            $result.Reachable | Should -BeTrue -Because (Get-CAStageSummary -StageResult $result.CAStageResult)
        }

        It 'Should give no Unavailability reason' {
            $result.CAUnavailabilityReason | Should -BeNullOrEmpty
        }

        It 'Should pass the DNS and transport Stages' {
            $result.CAStageResult.DNS.Passed | Should -BeTrue
            $result.CAStageResult.Transport.Passed | Should -BeTrue
        }
    }

    Context 'When the CA name is wrong but the host is right' {
        BeforeAll {
            $result = Test-CAAvailability -CAFullName "$labHost\No Such CA Name" -ComputerName $labHost
        }

        It 'Should not be Reachable' {
            $result.Reachable | Should -BeFalse
        }

        It 'Should give one of the reasons in the table, and not Unrecognized' {
            $result.CAUnavailabilityReason.Id | Should -BeIn $reasonIds
            $result.CAUnavailabilityReason.Id | Should -Not -Be 'Unrecognized' -Because (Get-CAStageSummary -StageResult $result.CAStageResult)
        }
    }

    Context 'When the host does not exist' {
        BeforeAll {
            $result = Test-CAAvailability -CAFullName 'nosuchhost.invalid\NoSuchCA' -ComputerName 'nosuchhost.invalid'
        }

        It 'Should not be Reachable, and the reason should be the DNS failure' {
            $result.Reachable | Should -BeFalse
            $result.CAUnavailabilityReason.Id | Should -Be 'HostNameNotResolved'
        }
    }

    Context 'When a registry value is read' {
        It 'Should read CA\Security' {
            $read = Invoke-CertutilGetReg -CAFullName $labCA -ComputerName $labHost -Path 'CA\Security'
            $read.Passed | Should -BeTrue -Because $read.Detail
        }

        It 'Should return 0x80070002 for a value that is not set' -Skip:(-not $absentRegistryPath) {
            $read = Invoke-CertutilGetReg -CAFullName $labCA -ComputerName $labHost -Path $env:LOCKSMITH_TEST_ABSENT_REG
            $read.Passed | Should -BeFalse
            $read.HResult | Should -Be ([int]0x80070002) -Because 'Set-AdditionalCAProperty treats this code as "value not set"'
        }
    }
}
