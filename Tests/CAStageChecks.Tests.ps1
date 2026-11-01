[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

BeforeDiscovery {
    $onWindows = $env:OS -eq 'Windows_NT'
}

BeforeAll {
    . $PSScriptRoot/../Private/Start-CADnsCheck.ps1
    . $PSScriptRoot/../Private/Start-CAIcmpCheck.ps1
    . $PSScriptRoot/../Private/Start-CATransportCheck.ps1
    . $PSScriptRoot/../Private/Start-CACertutilCheck.ps1
    . $PSScriptRoot/../Private/Complete-CAStage.ps1
}

Describe 'DNS Stage' {
    Context 'When the host name resolves' {
        BeforeAll {
            $result = Start-CADnsCheck -ComputerName 'localhost' | Complete-CAStage
        }

        It 'Should pass' {
            $result.Passed | Should -BeTrue
        }

        It 'Should report an address' {
            $result.Detail | Should -Match '\d'
        }

        It 'Should report elapsed milliseconds' {
            $result.ElapsedMs | Should -BeOfType [int]
        }
    }

    Context 'When the host name does not resolve' {
        BeforeAll {
            $unresolvableHost = 'nosuchhost.invalid'
            $result = Start-CADnsCheck -ComputerName $unresolvableHost | Complete-CAStage
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should explain why' {
            $result.Detail | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'ICMP Stage' {
    Context 'When the host answers a ping' {
        BeforeAll {
            $result = Start-CAIcmpCheck -ComputerName '127.0.0.1' | Complete-CAStage
        }

        It 'Should pass' {
            $result.Passed | Should -BeTrue
        }
    }

    Context 'When the host name does not resolve' {
        BeforeAll {
            $unresolvableHost = 'nosuchhost.invalid'
            $result = Start-CAIcmpCheck -ComputerName $unresolvableHost | Complete-CAStage
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should explain why' {
            $result.Detail | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When the host never answers' {
        BeforeAll {
            # 192.0.2.1 is TEST-NET-1 and is never routed.
            $unroutedHost = '192.0.2.1'
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Start-CAIcmpCheck -ComputerName $unroutedHost -TimeoutMilliseconds 500 | Complete-CAStage
            $stopwatch.Stop()
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should stop waiting at the timeout' {
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 3000
        }
    }
}

Describe 'Transport Stage' {
    Context 'When the port is open' {
        BeforeAll {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $openPort = $listener.LocalEndpoint.Port
            $result = Start-CATransportCheck -ComputerName '127.0.0.1' -Port $openPort | Complete-CAStage
        }

        AfterAll {
            $listener.Stop()
        }

        It 'Should pass' {
            $result.Passed | Should -BeTrue
        }

        It 'Should report the port it tried' {
            $result.Port | Should -Be $openPort
        }

        It 'Should describe the open port' {
            $result.Detail | Should -Be "TCP $openPort open"
        }
    }

    Context 'When the port is closed' {
        BeforeAll {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $closedPort = $listener.LocalEndpoint.Port
            $listener.Stop()
            $result = Start-CATransportCheck -ComputerName '127.0.0.1' -Port $closedPort | Complete-CAStage
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should explain why' {
            $result.Detail | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When the host never answers' {
        BeforeAll {
            $unroutedHost = '192.0.2.1'
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Start-CATransportCheck -ComputerName $unroutedHost -Port 135 -TimeoutMilliseconds 500 | Complete-CAStage
            $stopwatch.Stop()
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should stop waiting at the timeout' {
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 3000
        }
    }
}

Describe 'Certutil ping Stage on the local path' -Skip:(-not $onWindows) {
    Context 'When certutil cannot find the CA host' {
        BeforeAll {
            $unresolvableHost = 'nosuchhost.invalid'
            $result = Start-CACertutilCheck -CAFullName "$unresolvableHost\NoSuchCA" -ComputerName $unresolvableHost | Complete-CAStage
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should return the HResult as a number' {
            $result.HResult | Should -BeOfType [int]
            $result.HResult | Should -Not -Be 0
        }

        It 'Should not call it a timeout or a remote error' {
            $result.TimedOut | Should -BeFalse
            $result.RemoteError | Should -BeFalse
        }

        It 'Should keep the certutil text as detail' {
            $result.Detail | Should -Match 'certutil'
        }
    }

    Context 'When the host never answers' {
        BeforeAll {
            $unroutedHost = '192.0.2.1'
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Start-CACertutilCheck -CAFullName "$unroutedHost\NoSuchCA" -ComputerName $unroutedHost -TimeoutMilliseconds 500 | Complete-CAStage
            $stopwatch.Stop()
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should say it timed out' {
            $result.TimedOut | Should -BeTrue
            $result.Detail | Should -Be 'Timed out after 0.5s'
        }

        It 'Should stop waiting at the timeout' {
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 4000
        }
    }
}

Describe 'Certutil ping Stage on the credential path' {
    BeforeAll {
        $securePassword = [System.Security.SecureString]::new()
        foreach ($character in 'not-a-real-password'.ToCharArray()) { $securePassword.AppendChar($character) }
        $credential = [System.Management.Automation.PSCredential]::new('user', $securePassword)
    }

    Context 'When the remote certutil succeeds' {
        BeforeAll {
            Mock Invoke-Command {
                Start-Job -ScriptBlock { [pscustomobject]@{ ExitCode = 0; Output = 'CertUtil: -pingadmin command completed successfully.' } }
            }
            $result = Start-CACertutilCheck -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $credential | Complete-CAStage
        }

        It 'Should pass' {
            $result.Passed | Should -BeTrue
        }

        It 'Should run the command on the CA host' {
            $null = Start-CACertutilCheck -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $credential | Complete-CAStage
            Should -Invoke Invoke-Command -Exactly 1 -ParameterFilter { $ComputerName -eq 'ca1.corp.example' -and $AsJob }
        }
    }

    Context 'When the remote certutil fails' {
        BeforeAll {
            Mock Invoke-Command {
                Start-Job -ScriptBlock { [pscustomobject]@{ ExitCode = -2147024891; Output = 'CertUtil: -pingadmin command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)' } }
            }
            $result = Start-CACertutilCheck -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $credential | Complete-CAStage
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should return the remote exit code as the HResult' {
            $result.HResult | Should -Be (-2147024891)
        }

        It 'Should not call it a remote error' {
            $result.RemoteError | Should -BeFalse
        }
    }

    Context 'When the remote command itself fails' {
        BeforeAll {
            Mock Invoke-Command {
                Start-Job -ScriptBlock { throw 'WinRM cannot process the request.' }
            }
            $result = Start-CACertutilCheck -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $credential | Complete-CAStage
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should call it a remote error' {
            $result.RemoteError | Should -BeTrue
        }

        It 'Should keep the exception message as detail' {
            $result.Detail | Should -Match 'WinRM cannot process the request'
        }
    }

    Context 'When the remote command never finishes' {
        BeforeAll {
            Mock Invoke-Command {
                Start-Job -ScriptBlock { Start-Sleep -Seconds 60 }
            }
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Start-CACertutilCheck -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $credential -TimeoutMilliseconds 2000 | Complete-CAStage
            $stopwatch.Stop()
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should say it timed out' {
            $result.TimedOut | Should -BeTrue
            $result.Detail | Should -Be 'Timed out after 2s'
        }

        It 'Should stop the job and not wait for it' {
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 8000
            Get-Job | Where-Object { $_.State -eq 'Running' } | Should -BeNullOrEmpty
        }
    }
}

Describe 'Availability check code' {
    BeforeAll {
        $availabilityFiles = Get-ChildItem -Path $PSScriptRoot/../Private -Filter '*.ps1' |
            Where-Object { $_.Name -in 'Test-CAAvailability.ps1', 'Set-AdditionalCAProperty.ps1', 'Complete-CAStage.ps1' -or $_.Name -like 'Start-CA*Check.ps1' }
        $commandNames = foreach ($file in $availabilityFiles) {
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$parseErrors)
            $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() }
        }
    }

    It 'Should find the files to check' {
        $availabilityFiles.Count | Should -BeGreaterThan 5
    }

    It 'Should not use <_>, which cannot be given a timeout' -ForEach 'Test-NetConnection', 'Test-Connection' {
        $commandNames | Should -Not -Contain $_
    }
}
