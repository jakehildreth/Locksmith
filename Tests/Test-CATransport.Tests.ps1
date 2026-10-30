[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
param()

BeforeAll {
    . $PSScriptRoot/../Private/Test-CATransport.ps1
}

Describe 'Test-CATransport' {
    Context 'When the port is open' {
        BeforeAll {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $openPort = $listener.LocalEndpoint.Port
            $result = Test-CATransport -ComputerName '127.0.0.1' -Port $openPort -TimeoutMilliseconds 3000
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

        It 'Should report elapsed milliseconds' {
            $result.ElapsedMs | Should -BeOfType [int]
        }
    }

    Context 'When the port is closed' {
        BeforeAll {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $closedPort = $listener.LocalEndpoint.Port
            $listener.Stop()
            $result = Test-CATransport -ComputerName '127.0.0.1' -Port $closedPort -TimeoutMilliseconds 3000
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should explain why' {
            $result.Detail | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When the host name does not resolve' {
        BeforeAll {
            $unresolvableHost = 'nosuchhost.invalid'
            $result = Test-CATransport -ComputerName $unresolvableHost -Port 135 -TimeoutMilliseconds 3000
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
            # 192.0.2.1 is TEST-NET-1 and is never routed, so the connection can only time out or be rejected.
            $unroutedHost = '192.0.2.1'
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Test-CATransport -ComputerName $unroutedHost -Port 135 -TimeoutMilliseconds 500
            $stopwatch.Stop()
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should stop waiting at the timeout' {
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 3000
        }

        It 'Should explain why' {
            $result.Detail | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Set-AdditionalCAProperty availability check' {
    BeforeAll {
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot '../Private/Set-AdditionalCAProperty.ps1'), [ref]$null, [ref]$parseErrors)
        $commandNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() }
        $transportCall = $ast.FindAll({
                $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Test-CATransport'
            }, $true) | Select-Object -First 1
    }

    It 'Should parse without errors' {
        $parseErrors | Should -BeNullOrEmpty
    }

    It 'Should check the CA with the bounded Test-CATransport' {
        $commandNames | Should -Contain 'Test-CATransport'
    }

    It 'Should check the RPC endpoint mapper port' {
        $transportCall.Extent.Text | Should -Match '-Port\s+135\b'
    }

    It 'Should not use <_>, which cannot be given a timeout' -ForEach 'Test-NetConnection', 'Test-Connection' {
        $commandNames | Should -Not -Contain $_
    }
}
