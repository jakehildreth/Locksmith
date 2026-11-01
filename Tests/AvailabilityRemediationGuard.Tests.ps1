[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
param()

BeforeAll {
    # These checks read source files only, so they need no ActiveDirectory module and never skip.
    $parse = {
        param($Name)
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path "$PSScriptRoot/../$Name"), [ref]$null, [ref]$errors)
    }
    $parameterNames = {
        param($Ast)
        $Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $true) |
            ForEach-Object { $_.Name.VariablePath.UserPath }
    }
    $hashtableKeys = {
        param($Ast)
        $Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.HashtableAst] }, $true) |
            ForEach-Object { $_.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text.Trim("'", '"') } }
    }
}

# Fix on an AVAILABILITY row is a hint for a person, not a script.
# Invoke-Remediation turns Fix into a scriptblock and runs it after a confirmation.
Describe 'AVAILABILITY rows stay out of remediation and revert' {
    It 'Should not let <File> take an AVAILABILITY parameter' -ForEach @(
        @{ File = 'Private/Invoke-Remediation.ps1' }
        @{ File = 'Private/Export-RevertScript.ps1' }
    ) {
        $names = & $parameterNames (& $parse $File)
        $names | Should -Not -BeNullOrEmpty
        $names | Should -Not -Contain 'AvailabilityIssues'
    }

    It 'Should not pass AVAILABILITY rows to Invoke-Remediation or Export-RevertScript from Invoke-Locksmith' {
        $keys = & $hashtableKeys (& $parse 'Public/Invoke-Locksmith.ps1')
        $keys | Should -Contain 'AuditingIssues' -Because 'the Mode 4 parameter table must still be found'
        $keys | Should -Not -Contain 'AvailabilityIssues'
    }

    It 'Should not pass AVAILABILITY rows to Export-RevertScript from Invoke-Remediation' {
        $keys = & $hashtableKeys (& $parse 'Private/Invoke-Remediation.ps1')
        $keys | Should -Contain 'AuditingIssues' -Because 'the Export-RevertScript parameter table must still be found'
        $keys | Should -Not -Contain 'AvailabilityIssues'
    }
}
