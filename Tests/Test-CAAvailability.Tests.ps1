[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

BeforeAll {
    . $PSScriptRoot/../Private/Get-CAHResultReason.ps1
    . $PSScriptRoot/../Private/Get-CAUnavailabilityReason.ps1
    . $PSScriptRoot/../Private/Start-CADnsCheck.ps1
    . $PSScriptRoot/../Private/Start-CAIcmpCheck.ps1
    . $PSScriptRoot/../Private/Start-CATransportCheck.ps1
    . $PSScriptRoot/../Private/Start-CACertutilCheck.ps1
    . $PSScriptRoot/../Private/Complete-CAStage.ps1
    . $PSScriptRoot/../Private/Test-CAAvailability.ps1

    $securePassword = [System.Security.SecureString]::new()
    foreach ($character in 'not-a-real-password'.ToCharArray()) { $securePassword.AppendChar($character) }
    $testCredential = [System.Management.Automation.PSCredential]::new('user', $securePassword)

    # Each Stage mock records its call, so a test can check the order of Start and Complete.
    $script:calls = [System.Collections.Generic.List[string]]::new()
    $script:outcome = @{}

    Mock Start-CADnsCheck { $script:calls.Add('start:Dns'); [pscustomobject]@{ Kind = 'Dns' } }
    Mock Start-CAIcmpCheck { $script:calls.Add('start:Icmp'); [pscustomobject]@{ Kind = 'Icmp' } }
    Mock Start-CATransportCheck { $script:calls.Add("start:Transport:$Port"); [pscustomobject]@{ Kind = 'Transport'; Port = $Port } }
    Mock Start-CACertutilCheck { $script:calls.Add('start:Certutil'); [pscustomobject]@{ Kind = 'Certutil' } }
    Mock Complete-CAStage {
        param($Handle)
        $script:calls.Add("complete:$($Handle.Kind)")
        $key = if ($Handle.Kind -eq 'Transport') { "Transport$($Handle.Port)" } else { $Handle.Kind }
        $passed = if ($script:outcome.ContainsKey($key)) { $script:outcome[$key] } else { $true }
        $result = [ordered]@{ Passed = $passed; ElapsedMs = 1; Detail = "$key detail" }
        if ($Handle.Kind -eq 'Transport') { $result.Port = $Handle.Port }
        if ($Handle.Kind -eq 'Certutil') {
            $result.HResult = if ($passed) { $null } else { [int]0x800706ba }
            $result.TimedOut = $false
            $result.RemoteError = $false
        }
        [pscustomobject]$result
    }
}

Describe 'Test-CAAvailability' {
    BeforeEach {
        $script:calls.Clear()
        $script:outcome = @{}
    }

    Context 'When every Stage passes' {
        It 'Should be Reachable with no reason' {
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            $result.Reachable | Should -BeTrue
            $result.CAUnavailabilityReason | Should -BeNullOrEmpty
        }

        It 'Should return all four Stage results' {
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            $result.CAStageResult.PSObject.Properties.Name | Should -Be @('DNS', 'ICMP', 'Transport', 'Certutil')
        }
    }

    Context 'When only the certutil ping fails' {
        It 'Should not be Reachable' {
            $script:outcome = @{ Certutil = $false }
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            $result.Reachable | Should -BeFalse
        }

        It 'Should explain why' {
            $script:outcome = @{ Certutil = $false }
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            $result.CAUnavailabilityReason.Id | Should -Be 'ServiceNotAnswering'
        }
    }

    Context 'When every Stage except the certutil ping fails' {
        It 'Should still be Reachable, because only the certutil ping decides' {
            $script:outcome = @{ Dns = $false; Icmp = $false; Transport135 = $false }
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            $result.Reachable | Should -BeTrue
            $result.CAUnavailabilityReason | Should -BeNullOrEmpty
        }

        It 'Should still record the failed Stages' {
            $script:outcome = @{ Dns = $false; Icmp = $false; Transport135 = $false }
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            $result.CAStageResult.DNS.Passed | Should -BeFalse
            $result.CAStageResult.ICMP.Passed | Should -BeFalse
            $result.CAStageResult.Transport.Passed | Should -BeFalse
        }
    }

    Context 'When the Stages run' {
        It 'Should start every Stage before it completes any' {
            $null = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            $lastStart = ($script:calls | ForEach-Object -Begin { $i = 0 } -Process { if ($_ -like 'start:*') { $i }; $i++ } | Select-Object -Last 1)
            $firstComplete = [array]::IndexOf($script:calls.ToArray(), ($script:calls | Where-Object { $_ -like 'complete:*' } | Select-Object -First 1))
            $lastStart | Should -BeLessThan $firstComplete
        }

        It 'Should pass the fixed timeouts to the Stages' {
            $null = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            Should -Invoke Start-CADnsCheck -Exactly 1 -ParameterFilter { $TimeoutMilliseconds -eq 3000 }
            Should -Invoke Start-CAIcmpCheck -Exactly 1 -ParameterFilter { $TimeoutMilliseconds -eq 2000 }
            Should -Invoke Start-CATransportCheck -Exactly 1 -ParameterFilter { $TimeoutMilliseconds -eq 3000 }
            Should -Invoke Start-CACertutilCheck -Exactly 1 -ParameterFilter { $TimeoutMilliseconds -eq 10000 }
        }
    }

    Context 'When no credential is given' {
        It 'Should check TCP 135 only' {
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            Should -Invoke Start-CATransportCheck -Exactly 1 -ParameterFilter { $Port -eq 135 }
            $result.CAStageResult.Transport.Port | Should -Be 135
        }

        It 'Should not pass a credential to certutil' {
            $null = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example'
            Should -Invoke Start-CACertutilCheck -Exactly 1 -ParameterFilter { -not $Credential }
        }
    }

    Context 'When a credential is given' {
        It 'Should check WinRM on 5985 and 5986' {
            $null = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential
            Should -Invoke Start-CATransportCheck -Exactly 1 -ParameterFilter { $Port -eq 5985 }
            Should -Invoke Start-CATransportCheck -Exactly 1 -ParameterFilter { $Port -eq 5986 }
            Should -Invoke Start-CATransportCheck -Exactly 0 -ParameterFilter { $Port -eq 135 }
        }

        It 'Should pass the credential to certutil' {
            $null = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential
            Should -Invoke Start-CACertutilCheck -Exactly 1 -ParameterFilter { $Credential -eq $testCredential }
        }

        It 'Should report 5985 when it passes' {
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential
            $result.CAStageResult.Transport.Port | Should -Be 5985
        }

        It 'Should fall back to 5986 when only it passes' {
            $script:outcome = @{ Transport5985 = $false }
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential
            $result.CAStageResult.Transport.Port | Should -Be 5986
            $result.CAStageResult.Transport.Passed | Should -BeTrue
        }

        It 'Should report a failed transport on 5985 when both ports fail' {
            $script:outcome = @{ Transport5985 = $false; Transport5986 = $false }
            $result = Test-CAAvailability -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential
            $result.CAStageResult.Transport.Port | Should -Be 5985
            $result.CAStageResult.Transport.Passed | Should -BeFalse
        }
    }
}
