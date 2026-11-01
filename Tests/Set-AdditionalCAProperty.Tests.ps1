[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The helpers only build test objects.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'The placeholder Get-ADObject only gives Pester a command to mock.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'The placeholder Get-ADObject only gives Pester a command to mock.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '', Justification = 'The placeholder Get-ADObject only gives Pester a command to mock.')]
param()

BeforeDiscovery {
    # The real type ships with RSAT. Tests that need it skip on a machine without it.
    $adAvailable = [bool]('Microsoft.ActiveDirectory.Management.ADEntity' -as [type])
}

BeforeAll {
    . $PSScriptRoot/../Private/Get-CAHResultReason.ps1
    . $PSScriptRoot/../Private/Invoke-CertutilGetReg.ps1
    . $PSScriptRoot/../Private/Test-CAAvailability.ps1
    . $PSScriptRoot/../Private/Set-AdditionalCAProperty.ps1

    if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        function Get-ADObject { param($Filter, $Properties, $Server, $Credential) }
    }

    function New-TestCA {
        param([string]$Name = 'CA1')
        $entityType = 'Microsoft.ActiveDirectory.Management.ADEntity' -as [type]
        $ca = try { $entityType::new() } catch { New-Object -TypeName Microsoft.ActiveDirectory.Management.ADObject }
        # 'localhost' keeps the unrelated enrollment endpoint probes fast and offline.
        Add-Member -InputObject $ca -MemberType NoteProperty -Name objectClass -Value 'pKIEnrollmentService' -Force
        Add-Member -InputObject $ca -MemberType NoteProperty -Name Name -Value $Name -Force
        Add-Member -InputObject $ca -MemberType NoteProperty -Name dNSHostName -Value 'localhost' -Force
        $ca
    }

    function New-Availability {
        param([bool]$Reachable = $true)
        $reason = if ($Reachable) { $null } else {
            [pscustomobject]@{ Id = 'ServiceNotAnswering'; Text = 'CA service not answering'; Sentence = 'sentence'; Hint = 'hint' }
        }
        [pscustomobject]@{
            Reachable              = $Reachable
            CAStageResult          = [pscustomobject]@{ Marker = 'stages' }
            CAUnavailabilityReason = $reason
        }
    }

    function New-Read {
        param([string[]]$Output = @(), $HResult = $null, [bool]$RemoteError = $false, [string]$Detail = '')
        $passed = ($null -eq $HResult) -and -not $RemoteError
        [pscustomobject]@{ Passed = $passed; HResult = $HResult; Output = $Output; Detail = $Detail; RemoteError = $RemoteError }
    }

    function Get-GoodRead {
        @{
            'CA\AuditFilter'             = New-Read -Output @('Value AuditFilter REG_DWORD = 7f (127)')
            'policy\EditFlags'           = New-Read -Output @('  EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)')
            'CA\InterfaceFlags'          = New-Read -Output @('  IF_ENFORCEENCRYPTICERTREQUEST -- 200 (512)')
            'CA\Security'                = New-Read -Output @("  Allow`tCA Administrator`tCORP\Domain Admins", "  Allow`tCertificate Manager`tCORP\PKI Managers")
            'policy\DisableExtensionList' = New-Read -Output @('  1.3.6.1.4.1.311.25.2')
        }
    }

    Mock Get-ADObject { [pscustomobject]@{ DistinguishedName = 'CN=ca1,OU=Servers,DC=corp,DC=example'; DnsHostname = 'ca1.corp.example' } }
    Mock Test-CAAvailability {
        if ($script:availabilityByName.ContainsKey($CAFullName)) { $script:availabilityByName[$CAFullName] } else { $script:availability }
    }
    Mock Invoke-CertutilGetReg {
        if ($script:reads.ContainsKey("$CAFullName|$Path")) { $script:reads["$CAFullName|$Path"] } else { $script:reads[$Path] }
    }
}

Describe 'Set-AdditionalCAProperty' -Skip:(-not $adAvailable) {
    BeforeEach {
        $script:availability = New-Availability
        $script:availabilityByName = @{}
        $script:reads = Get-GoodRead
    }

    Context 'When the CA is Reachable and every read passes' {
        BeforeAll {
            $script:availability = New-Availability
            $script:availabilityByName = @{}
            $script:reads = Get-GoodRead
            $ca = New-TestCA
            Set-AdditionalCAProperty -ADCSObjects $ca -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should be Reachable with no reason' {
            $ca.Reachable | Should -BeTrue
            $ca.CAUnavailabilityReason | Should -BeNull
        }

        It 'Should have no read failures' {
            $ca.CAReadFailure.Count | Should -Be 0
        }

        It 'Should attach the Stage results' {
            $ca.CAStageResult.Marker | Should -Be 'stages'
        }

        It 'Should parse the values' {
            $ca.AuditFilter | Should -Be '127'
            $ca.SANFlag | Should -Be 'Yes'
            $ca.InterfaceFlag | Should -Be 'Yes'
            $ca.DisableExtensionList | Should -Be 'Yes'
        }

        It 'Should parse the CA principals' {
            $ca.CAAdministrator | Should -Contain 'CORP\Domain Admins'
            $ca.CertificateManager | Should -Contain 'CORP\PKI Managers'
        }
    }

    Context 'When the CA is not Reachable' {
        BeforeAll {
            $script:availability = New-Availability -Reachable $false
            $script:availabilityByName = @{}
            $script:reads = Get-GoodRead
            $ca = New-TestCA
            Set-AdditionalCAProperty -ADCSObjects $ca -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should not be Reachable and should say why' {
            $ca.Reachable | Should -BeFalse
            $ca.CAUnavailabilityReason.Id | Should -Be 'ServiceNotAnswering'
        }

        It 'Should leave every value null and never store a sentinel string' {
            foreach ($name in 'AuditFilter', 'SANFlag', 'InterfaceFlag', 'CAAdministrator', 'CertificateManager', 'DisableExtensionList') {
                $ca.$name | Should -BeNull -Because "$name must be null"
            }
        }

        It 'Should leave the read failures empty, because the reason covers every property' {
            $ca.CAReadFailure.Count | Should -Be 0
        }

        It 'Should not try to read the CA' {
            $script:availability = New-Availability -Reachable $false
            $null = New-TestCA | Set-AdditionalCAProperty -ForestGC 'dc1.corp.example:3268'
            Should -Invoke Invoke-CertutilGetReg -Exactly 0
        }
    }

    Context 'When a value was never set (0x80070002)' {
        BeforeAll {
            $script:availability = New-Availability
            $script:availabilityByName = @{}
            $script:reads = Get-GoodRead
            foreach ($path in 'CA\AuditFilter', 'policy\EditFlags', 'CA\InterfaceFlags', 'policy\DisableExtensionList') {
                $script:reads[$path] = New-Read -HResult ([int]0x80070002) -Detail 'file not found'
            }
            $ca = New-TestCA
            Set-AdditionalCAProperty -ADCSObjects $ca -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should keep the results of an unset value' {
            $ca.AuditFilter | Should -Be 'Never Configured'
            $ca.SANFlag | Should -Be 'No'
            $ca.InterfaceFlag | Should -Be 'No'
            $ca.DisableExtensionList | Should -Be 'No'
        }

        It 'Should not report a read failure' {
            $ca.CAReadFailure.Count | Should -Be 0
        }
    }

    Context 'When the CA\Security read is denied' {
        BeforeAll {
            $script:availability = New-Availability
            $script:availabilityByName = @{}
            $script:reads = Get-GoodRead
            $script:reads['CA\Security'] = New-Read -HResult ([int]0x80070005) -Detail 'access denied'
            $ca = New-TestCA
            Set-AdditionalCAProperty -ADCSObjects $ca -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should be Reachable' {
            $ca.Reachable | Should -BeTrue
        }

        It 'Should leave the principal lists null' {
            $ca.CAAdministrator | Should -BeNull
            $ca.CertificateManager | Should -BeNull
        }

        It 'Should record the reason for both principal lists' {
            $ca.CAReadFailure['CAAdministrator'] | Should -Be 'Access denied (0x80070005)'
            $ca.CAReadFailure['CertificateManager'] | Should -Be 'Access denied (0x80070005)'
        }

        It 'Should still parse the reads that passed' {
            $ca.SANFlag | Should -Be 'Yes'
            $ca.AuditFilter | Should -Be '127'
        }
    }

    Context 'When CA\Security returns 0x80070002' {
        BeforeAll {
            $script:availability = New-Availability
            $script:availabilityByName = @{}
            $script:reads = Get-GoodRead
            $script:reads['CA\Security'] = New-Read -HResult ([int]0x80070002) -Detail 'file not found'
            $ca = New-TestCA
            Set-AdditionalCAProperty -ADCSObjects $ca -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should count it as a failed read, because that key always exists' {
            $ca.CAAdministrator | Should -BeNull
            $ca.CAReadFailure['CAAdministrator'] | Should -Be 'CA not found at that name (0x80070002)'
        }
    }

    Context 'When a value read fails with another HResult' {
        BeforeAll {
            $script:availability = New-Availability
            $script:availabilityByName = @{}
            $script:reads = Get-GoodRead
            $script:reads['policy\EditFlags'] = New-Read -HResult ([int]0x80070005) -Detail 'access denied'
            $ca = New-TestCA
            Set-AdditionalCAProperty -ADCSObjects $ca -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should leave the value null, never No' {
            $ca.SANFlag | Should -BeNull
        }

        It 'Should record the reason under the property name' {
            $ca.CAReadFailure['SANFlag'] | Should -Be 'Access denied (0x80070005)'
        }
    }

    Context 'When a remote read fails on the credential path' {
        BeforeAll {
            $script:availability = New-Availability
            $script:availabilityByName = @{}
            $script:reads = Get-GoodRead
            $script:reads['CA\InterfaceFlags'] = New-Read -RemoteError $true -Detail 'WinRM cannot process the request.'
            $ca = New-TestCA
            Set-AdditionalCAProperty -ADCSObjects $ca -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should explain that the remote command failed' {
            $ca.InterfaceFlag | Should -BeNull
            $ca.CAReadFailure['InterfaceFlag'] | Should -Be 'Remote command failed: WinRM cannot process the request.'
        }
    }

    Context 'When one CA is Reachable and the next is not' {
        BeforeAll {
            $script:availability = New-Availability
            $script:availabilityByName = @{ 'localhost\CA2' = New-Availability -Reachable $false }
            $script:reads = Get-GoodRead
            $firstCA = New-TestCA -Name 'CA1'
            $secondCA = New-TestCA -Name 'CA2'
            Set-AdditionalCAProperty -ADCSObjects @($firstCA, $secondCA) -ForestGC 'dc1.corp.example:3268'
        }

        It 'Should keep the data of the first CA' {
            $firstCA.AuditFilter | Should -Be '127'
            $firstCA.CAAdministrator | Should -Contain 'CORP\Domain Admins'
        }

        It 'Should not let the second CA inherit the first CA''s data' {
            foreach ($name in 'AuditFilter', 'SANFlag', 'InterfaceFlag', 'CAAdministrator', 'CertificateManager', 'DisableExtensionList') {
                $secondCA.$name | Should -BeNull -Because "$name of an unavailable CA must not come from the previous CA"
            }
            $secondCA.Reachable | Should -BeFalse
        }
    }

    Context 'When a credential is given' {
        BeforeAll {
            $securePassword = [System.Security.SecureString]::new()
            foreach ($character in 'not-a-real-password'.ToCharArray()) { $securePassword.AppendChar($character) }
            $testCredential = [System.Management.Automation.PSCredential]::new('user', $securePassword)
        }

        It 'Should pass the credential to the Availability check and to every read' {
            $null = New-TestCA | Set-AdditionalCAProperty -Credential $testCredential -ForestGC 'dc1.corp.example:3268'
            Should -Invoke Test-CAAvailability -Exactly 1 -ParameterFilter { $Credential -eq $testCredential }
            Should -Invoke Invoke-CertutilGetReg -Exactly 5 -ParameterFilter { $Credential -eq $testCredential }
        }
    }

    Context 'When the host name lookup in AD finds nothing' {
        BeforeAll {
            Mock Get-ADObject { $null }
        }

        It 'Should fall back to the CA''s own host name and still run the check' {
            $null = New-TestCA | Set-AdditionalCAProperty -ForestGC 'dc1.corp.example:3268' -WarningAction SilentlyContinue
            Should -Invoke Test-CAAvailability -Exactly 1 -ParameterFilter { $ComputerName -eq 'localhost' }
        }
    }
}
