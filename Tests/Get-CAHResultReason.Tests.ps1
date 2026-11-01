[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
param()

BeforeAll {
    . $PSScriptRoot/../Private/Get-CAHResultReason.ps1
}

Describe 'Get-CAHResultReason' {
    Context 'When the HResult is known' {
        It 'Should map <HResultText> to <Id>' -ForEach @(
            @{ HResult = 0x800706ba; HResultText = '0x800706ba'; Id = 'ServiceNotAnswering' }
            @{ HResult = 0x80040154; HResultText = '0x80040154'; Id = 'CANotFound' }
            @{ HResult = 0x80070002; HResultText = '0x80070002'; Id = 'CANotFound' }
            @{ HResult = 0x80070043; HResultText = '0x80070043'; Id = 'CANotFound' }
            @{ HResult = 0x80070035; HResultText = '0x80070035'; Id = 'CANotFound' }
            @{ HResult = 0x80070005; HResultText = '0x80070005'; Id = 'AccessDenied' }
        ) {
            (Get-CAHResultReason -HResult $HResult).Id | Should -Be $Id
        }

        It 'Should accept the negative exit code that certutil returns' {
            (Get-CAHResultReason -HResult (-2147023174)).Id | Should -Be 'ServiceNotAnswering'
        }

        It 'Should include the HResult in the text' {
            (Get-CAHResultReason -HResult 0x80070005).Text | Should -Be 'Access denied (0x80070005)'
        }
    }

    Context 'When the HResult proves the host answered' {
        It 'Should say so for <HResultText>' -ForEach @(
            @{ HResult = 0x80070005; HResultText = '0x80070005' }
            @{ HResult = 0x80040154; HResultText = '0x80040154' }
        ) {
            (Get-CAHResultReason -HResult $HResult).ProvesHostAnswered | Should -BeTrue
        }

        It 'Should not say so for <HResultText>' -ForEach @(
            @{ HResult = 0x800706ba; HResultText = '0x800706ba' }
            @{ HResult = 0x80070002; HResultText = '0x80070002' }
            @{ HResult = 0x80070035; HResultText = '0x80070035' }
        ) {
            (Get-CAHResultReason -HResult $HResult).ProvesHostAnswered | Should -BeFalse
        }
    }

    Context 'When the HResult is not in the table' {
        It 'Should be an unrecognized failure' {
            (Get-CAHResultReason -HResult 0x12345678).Id | Should -Be 'Unrecognized'
        }

        It 'Should show the HResult in the text' {
            (Get-CAHResultReason -HResult 0x12345678).Text | Should -Be 'Unrecognized failure (0x12345678)'
        }

        It 'Should not treat the WinINet codes from issue 228 as known' -ForEach @(
            @{ HResult = 0x80072efd }
            @{ HResult = 0x80072ee7 }
        ) {
            (Get-CAHResultReason -HResult $HResult).Id | Should -Be 'Unrecognized'
        }
    }
}
