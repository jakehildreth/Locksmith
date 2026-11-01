[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

BeforeDiscovery {
    # The real type ships with RSAT. Tests that need it skip on a machine without it.
    $adAvailable = [bool]('Microsoft.ActiveDirectory.Management.ADEntity' -as [type])
}

BeforeAll {
    . $PSScriptRoot/../Private/Get-CAHResultReason.ps1
    . $PSScriptRoot/../Private/Get-CAUnavailabilityReason.ps1
    . $PSScriptRoot/../Private/Get-CAStageSummary.ps1
    . $PSScriptRoot/../Private/Set-RiskRating.ps1
    . $PSScriptRoot/../Private/Find-AvailabilityIssue.ps1
    . $PSScriptRoot/TestHelper.ps1

    $unsafeUsers = 'S-1-1-0|S-1-5-11'
    $safeUsers = 'S-1-5-32-544'
    $stageLine = 'Stages: DNS ok, ICMP failed, TCP 135 ok, certutil 0x800706ba.'
}

Describe 'Find-AvailabilityIssue' -Skip:(-not $adAvailable) {
    Context 'When every CA was fully read' {
        It 'Should report nothing' {
            $result = @(Find-AvailabilityIssue -ADCSObjects (New-TestCA) -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers -SkipRisk)
            $result.Count | Should -Be 0
        }

        It 'Should ignore an object that never went through the Availability check' {
            $notChecked = New-TestADEntity -Property @{ objectClass = 'pKIEnrollmentService'; Name = 'CA1'; CanonicalName = 'corp.example/x/CA1' }
            @(Find-AvailabilityIssue -ADCSObjects $notChecked -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
        }

        It 'Should ignore objects that are not CAs' {
            $template = New-TestCA -Property @{ objectClass = 'pKICertificateTemplate'; Reachable = $false }
            @(Find-AvailabilityIssue -ADCSObjects $template -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
        }
    }

    Context 'When a CA is not Reachable' {
        BeforeAll {
            $ca = New-TestUnreachableCA
            $result = @(Find-AvailabilityIssue -ADCSObjects $ca -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers -SkipRisk)
        }

        It 'Should return one consolidated row' {
            $result.Count | Should -Be 1
            $result[0].Technique | Should -Be 'AVAILABILITY'
        }

        It 'Should identify the CA' {
            $result[0].Name | Should -Be 'CA1'
            $result[0].Forest | Should -Be 'corp.example'
            $result[0].CAFullName | Should -Be 'ca1.corp.example\CA1'
            $result[0].DistinguishedName | Should -Be $ca.DistinguishedName
        }

        It 'Should lay out the Issue as cause, not evaluated, then Stages' {
            $result[0].Issue | Should -Be "The host responds, but the CA service did not answer (0x800706ba). Not evaluated: DETECT, ESC6, ESC7, ESC11, ESC16. $stageLine"
        }

        It 'Should give a one-line hint as the Fix' {
            $result[0].Fix | Should -Be "Check that the 'certsvc' service is running on ca1.corp.example."
        }

        It 'Should have nothing to revert' {
            $result[0].Revert | Should -Be 'N/A'
        }

        It 'Should not use the word reachable in the cause sentence' {
            $result[0].Issue | Should -Not -Match 'reachable'
        }
    }

    Context 'When a CA is Reachable but one read failed' {
        BeforeAll {
            $ca = New-TestCA -Property @{
                AuditFilter        = $null
                CAAdministrator    = $null
                CertificateManager = $null
                CAReadFailure      = @{
                    CAAdministrator    = 'Access denied (0x80070005)'
                    CertificateManager = 'Access denied (0x80070005)'
                }
            }
            $result = @(Find-AvailabilityIssue -ADCSObjects $ca -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers -SkipRisk)
        }

        It 'Should still be one row for the CA' {
            $result.Count | Should -Be 1
            $result[0].Technique | Should -Be 'AVAILABILITY'
        }

        It 'Should list the failed reads once per reason and name only ESC7 as not evaluated' {
            $result[0].Issue | Should -Be 'Partly evaluated. Could not read: CAAdministrator, CertificateManager (Access denied (0x80070005)). Not evaluated: ESC7. Stages: DNS ok, ICMP ok, TCP 135 ok, certutil ok.'
        }

        It 'Should hint at the rights needed for an access denied failure' {
            $result[0].Fix | Should -Be 'Run Locksmith as a CA Administrator, or supply -Credential.'
        }
    }

    Context 'When different reads fail for different reasons' {
        BeforeAll {
            $ca = New-TestCA -Property @{
                AuditFilter   = $null
                SANFlag       = $null
                CAReadFailure = @{
                    AuditFilter = 'Access denied (0x80070005)'
                    SANFlag     = 'Remote command failed: WinRM cannot process the request.'
                }
            }
            $result = @(Find-AvailabilityIssue -ADCSObjects $ca -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers -SkipRisk)
        }

        It 'Should list each reason with its properties and name each technique once' {
            $result[0].Issue | Should -Match 'Could not read: AuditFilter \(Access denied \(0x80070005\)\); SANFlag \(Remote command failed: WinRM cannot process the request\.\)\.'
            $result[0].Issue | Should -Match 'Not evaluated: DETECT, ESC6\.'
        }
    }

    Context 'When more than one CA has a problem' {
        It 'Should return one row for each CA with a problem and none for a healthy CA' {
            $cas = @((New-TestCA -Name 'CA1'), (New-TestUnreachableCA -Name 'CA2'), (New-TestUnreachableCA -Name 'CA3'))
            $result = @(Find-AvailabilityIssue -ADCSObjects $cas -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers -SkipRisk)
            $result.Name | Should -Be @('CA2', 'CA3')
        }
    }

    Context 'When risk rating is on' {
        BeforeAll {
            Mock Set-RiskRating { }
        }

        It 'Should rate each row' {
            $null = Find-AvailabilityIssue -ADCSObjects (New-TestUnreachableCA) -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers
            Should -Invoke Set-RiskRating -Exactly 1 -ParameterFilter { $Issue.Technique -eq 'AVAILABILITY' }
        }
    }
}

Describe 'Set-RiskRating for AVAILABILITY' -Skip:(-not $adAvailable) {
    It 'Should rate an AVAILABILITY row as Medium, like the placeholder rows it replaces' {
        $issue = [pscustomobject]@{ Technique = 'AVAILABILITY'; Name = 'CA1' }
        Set-RiskRating -ADCSObjects (New-TestCA) -Issue $issue -SafeUsers $safeUsers -UnsafeUsers $unsafeUsers
        $issue.RiskName | Should -Be 'Medium'
        $issue.RiskValue | Should -Be 3
    }
}
