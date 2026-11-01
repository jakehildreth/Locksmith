[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
param()

BeforeAll {
    . $PSScriptRoot/../Private/Write-HostColorized.ps1
    . $PSScriptRoot/../Private/Format-Result.ps1

    $script:rendered = ''
    Mock Write-Host { $script:rendered += "$Object" }

    $availabilityRow = [pscustomobject]@{
        Technique = 'AVAILABILITY'; Name = 'CA1'; Issue = 'A cause. Not evaluated: DETECT. Stages: DNS ok.'; Fix = 'A hint.'
        RiskName = 'Medium'; RiskValue = 3; RiskScoring = @('Base Score: 3'); DistinguishedName = 'CN=CA1'
    }
}

# Invoke-Scans stores a scan with no findings as an empty array (ESC3 always does), and an empty array is not $null.
# Format-Result used to look up a title for no technique, which throws. Under $ErrorActionPreference = 'Stop' that
# error ended Invoke-Locksmith, and the findings after it were never shown.
Describe 'Format-Result with nothing to report' {
    BeforeEach {
        $script:rendered = ''
    }

    It 'Should write nothing for <Name> in Mode <Mode>' -ForEach @(
        @{ Name = 'an empty array'; Issue = [array]@(); Mode = 0 }
        @{ Name = 'an empty array'; Issue = [array]@(); Mode = 1 }
        @{ Name = '$null'; Issue = $null; Mode = 0 }
        @{ Name = '$null'; Issue = $null; Mode = 1 }
    ) {
        Format-Result -Issue $Issue -Mode $Mode
        $script:rendered | Should -BeNullOrEmpty
        Should -Invoke Write-Host -Exactly 0
    }

    It 'Should not throw for an empty array when ErrorActionPreference is Stop' {
        $previous = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Stop'
            { Format-Result -Issue ([array]@()) -Mode 0 } | Should -Not -Throw
        } finally {
            $ErrorActionPreference = $previous
        }
    }

    It 'Should not write an error for an empty array' {
        $errors = @()
        Format-Result -Issue ([array]@()) -Mode 0 -ErrorVariable errors -ErrorAction SilentlyContinue
        $errors.Count | Should -Be 0
    }
}

Describe 'Format-Result with a finding' {
    BeforeEach {
        $script:rendered = ''
    }

    It 'Should still show a single row in Mode <Mode>' -ForEach @(@{ Mode = 0 }, @{ Mode = 1 }) {
        Format-Result -Issue $availabilityRow -Mode $Mode
        $script:rendered | Should -Match 'Certification Authority Not Fully Evaluated'
        $script:rendered | Should -Match 'A cause\.'
    }

    It 'Should still show an array of rows in Mode <Mode>' -ForEach @(@{ Mode = 0 }, @{ Mode = 1 }) {
        Format-Result -Issue @($availabilityRow, $availabilityRow) -Mode $Mode
        $script:rendered | Should -Match 'Certification Authority Not Fully Evaluated'
    }
}
