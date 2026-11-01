[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables from BeforeAll with the It blocks, which the analyzer cannot see.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

BeforeDiscovery {
    # The real type ships with RSAT. Tests that need it skip on a machine without it.
    $adAvailable = [bool]('Microsoft.ActiveDirectory.Management.ADEntity' -as [type])
}

BeforeAll {
    foreach ($file in Get-ChildItem -Path $PSScriptRoot/../Private -Filter 'Find-*.ps1') {
        . $file.FullName
    }
    . $PSScriptRoot/../Private/Get-CAHResultReason.ps1
    . $PSScriptRoot/../Private/Get-CAUnavailabilityReason.ps1
    . $PSScriptRoot/../Private/Get-CAStageSummary.ps1
    . $PSScriptRoot/../Private/Invoke-Scans.ps1
    . $PSScriptRoot/../Private/Write-HostColorized.ps1
    . $PSScriptRoot/../Private/Format-Result.ps1
    . $PSScriptRoot/TestHelper.ps1

    $availabilityRow = [pscustomobject]@{
        Technique = 'AVAILABILITY'; Name = 'CA1'; Issue = 'A cause. Not evaluated: DETECT. Stages: DNS ok.'; Fix = 'A hint.'; Revert = 'N/A'
        RiskName = 'Medium'; RiskValue = 3; RiskScoring = @('Base Score: 3'); DistinguishedName = 'CN=CA1'
    }

    # Every finder returns nothing unless a test says otherwise.
    foreach ($finder in (Get-Command -Name 'Find-*' -CommandType Function | Where-Object { $_.Name -ne 'Find-AvailabilityIssue' })) {
        Mock -CommandName $finder.Name -MockWith { }
    }
    Mock Find-AvailabilityIssue { $availabilityRow }
    $script:rendered = ''
    Mock Write-Host { $script:rendered += "$Object" }

    $scanParameters = @{
        ClientAuthEkus     = 'x'
        ServerAuthEkus     = 'x'
        DangerousRights    = 'x'
        EnrollmentAgentEKU = 'x'
        Mode               = 0
        SafeObjectTypes    = 'x'
        SafeUsers          = 'S-1-5-32-544'
        SafeOwners         = 'x'
        UnsafeUsers        = 'S-1-1-0'
        PreferredOwner     = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    }
}

Describe 'Invoke-Scans and AVAILABILITY rows' -Skip:(-not $adAvailable) {
    It 'Should look for AVAILABILITY rows when the <Scan> scan runs' -ForEach @(
        @{ Scan = 'All' }
        @{ Scan = 'Auditing' }
        @{ Scan = 'ESC6' }
        @{ Scan = 'ESC7' }
        @{ Scan = 'ESC11' }
        @{ Scan = 'ESC16' }
    ) {
        $results = Invoke-Scans -ADCSObjects (New-TestCA) -Scans $Scan @scanParameters
        Should -Invoke Find-AvailabilityIssue -Exactly 1
        $results['AvailabilityIssues'].Technique | Should -Be 'AVAILABILITY'
    }

    It 'Should not look for AVAILABILITY rows when only template scans run' {
        Mock Find-ESC1 { [pscustomobject]@{ Technique = 'ESC1' } }
        $results = Invoke-Scans -ADCSObjects (New-TestCA) -Scans 'ESC1' @scanParameters
        Should -Invoke Find-AvailabilityIssue -Exactly 0
        $results['AvailabilityIssues'] | Should -BeNullOrEmpty
    }

    It 'Should include the AVAILABILITY rows in AllIssues, so Modes 2 and 3 write them to the CSV' {
        $results = Invoke-Scans -ADCSObjects (New-TestCA) -Scans 'ESC6' @scanParameters
        $results['AllIssues'].Technique | Should -Contain 'AVAILABILITY'
    }

    It 'Should not report that no issues were found when the only problem is an unreadable CA' {
        $results = Invoke-Scans -ADCSObjects (New-TestCA) -Scans 'ESC6' @scanParameters
        $results | Should -Not -BeNullOrEmpty
    }
}

Describe 'Format-Result for AVAILABILITY' -Skip:(-not $adAvailable) {
    It 'Should show the row in Mode <Mode>' -ForEach @(@{ Mode = 0 }, @{ Mode = 1 }) {
        $script:rendered = ''
        { Format-Result -Issue $availabilityRow -Mode $Mode } | Should -Not -Throw
        $script:rendered | Should -Match 'Certification Authority Not Fully Evaluated'
        $script:rendered | Should -Match 'AVAILABILITY'
        $script:rendered | Should -Match 'A cause\.'
    }
}
