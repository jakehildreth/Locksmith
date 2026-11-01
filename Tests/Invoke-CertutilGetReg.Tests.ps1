[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

BeforeDiscovery {
    $onWindows = $env:OS -eq 'Windows_NT'
}

BeforeAll {
    . $PSScriptRoot/../Private/Invoke-CertutilGetReg.ps1

    $securePassword = [System.Security.SecureString]::new()
    foreach ($character in 'not-a-real-password'.ToCharArray()) { $securePassword.AppendChar($character) }
    $testCredential = [System.Management.Automation.PSCredential]::new('user', $securePassword)
}

Describe 'Invoke-CertutilGetReg on the local path' -Skip:(-not $onWindows) {
    Context 'When certutil cannot find the CA host' {
        BeforeAll {
            $unresolvableHost = 'nosuchhost.invalid'
            $result = Invoke-CertutilGetReg -CAFullName "$unresolvableHost\NoSuchCA" -ComputerName $unresolvableHost -Path 'CA\AuditFilter'
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should return the HResult as a number' {
            $result.HResult | Should -Be ([int]0x80070035)
        }

        It 'Should keep the certutil text as detail' {
            $result.Detail | Should -Match 'certutil'
        }

        It 'Should not call it a remote error' {
            $result.RemoteError | Should -BeFalse
        }
    }
}

Describe 'Invoke-CertutilGetReg on the credential path' {
    Context 'When the read succeeds' {
        BeforeAll {
            Mock Invoke-Command { [pscustomobject]@{ ExitCode = 0; Output = @('Value AuditFilter REG_DWORD = 7f (127)', 'CertUtil: -getreg command completed successfully.') } }
            $result = Invoke-CertutilGetReg -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential -Path 'CA\AuditFilter'
        }

        It 'Should pass' {
            $result.Passed | Should -BeTrue
        }

        It 'Should return the output lines' {
            $result.Output | Should -Contain 'Value AuditFilter REG_DWORD = 7f (127)'
        }

        It 'Should have no HResult' {
            $result.HResult | Should -BeNullOrEmpty
        }

        It 'Should run the command on the CA host with the credential' {
            $null = Invoke-CertutilGetReg -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential -Path 'CA\AuditFilter'
            Should -Invoke Invoke-Command -Exactly 1 -ParameterFilter { $ComputerName -eq 'ca1.corp.example' -and $Credential -eq $testCredential }
        }
    }

    Context 'When certutil returns an error' {
        BeforeAll {
            Mock Invoke-Command { [pscustomobject]@{ ExitCode = -2147024891; Output = @('CertUtil: -getreg command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)') } }
            $result = Invoke-CertutilGetReg -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential -Path 'CA\Security'
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should return the exit code as the HResult' {
            $result.HResult | Should -Be ([int]0x80070005)
        }

        It 'Should not call it a remote error' {
            $result.RemoteError | Should -BeFalse
        }
    }

    Context 'When the exit code is missing but the text has an HResult' {
        BeforeAll {
            Mock Invoke-Command { [pscustomobject]@{ ExitCode = $null; Output = @('CertUtil: -getreg command FAILED: 0x80070002 (WIN32: 2 ERROR_FILE_NOT_FOUND)') } }
            $result = Invoke-CertutilGetReg -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential -Path 'policy\DisableExtensionList'
        }

        It 'Should fail' {
            $result.Passed | Should -BeFalse
        }

        It 'Should read the HResult from the text' {
            $result.HResult | Should -Be ([int]0x80070002)
        }
    }

    Context 'When the remote command itself fails' {
        BeforeAll {
            Mock Invoke-Command { throw 'WinRM cannot process the request.' }
            $result = Invoke-CertutilGetReg -CAFullName 'ca1.corp.example\CA' -ComputerName 'ca1.corp.example' -Credential $testCredential -Path 'CA\AuditFilter'
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
}
