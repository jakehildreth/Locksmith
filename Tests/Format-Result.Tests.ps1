BeforeAll {
    . $PSScriptRoot/../Private/Format-Result.ps1
}

Describe 'Format-Result' {
    Context 'When there are no issues to format' {
        It 'Should not throw for $null' {
            { Format-Result -Issue $null -Mode 0 } | Should -Not -Throw
        }

        # Regression: the ESC3 scan returns @() when nothing is found, which previously threw
        # "Index operation failed; the array index evaluated to null."
        It 'Should not throw for an empty array in Mode <Mode>' -ForEach @(
            @{ Mode = 0 }
            @{ Mode = 1 }
        ) {
            { Format-Result -Issue @() -Mode $Mode } | Should -Not -Throw
        }

        It 'Should write nothing for an empty array' {
            Mock Write-Host { }
            Format-Result -Issue @() -Mode 0
            Should -Invoke Write-Host -Times 0 -Exactly
        }
    }
}
