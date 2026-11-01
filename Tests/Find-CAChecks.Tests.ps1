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
    . $PSScriptRoot/../Private/Convert-IdentityReferenceToSid.ps1
    . $PSScriptRoot/../Private/Set-RiskRating.ps1
    . $PSScriptRoot/../Private/Find-AuditingIssue.ps1
    . $PSScriptRoot/../Private/Find-ESC6.ps1
    . $PSScriptRoot/../Private/Find-ESC7.ps1
    . $PSScriptRoot/../Private/Find-ESC11.ps1
    . $PSScriptRoot/../Private/Find-ESC16.ps1
    . $PSScriptRoot/TestHelper.ps1

    $unsafeUsers = 'S-1-1-0|S-1-5-11'
    $safeUsers = 'S-1-5-32-544'
}

Describe 'Find-AuditingIssue' -Skip:(-not $adAvailable) {
    It 'Should report AuditFilter <Value> as a DETECT issue' -ForEach @(
        @{ Value = '0' }
        @{ Value = '66' }
        @{ Value = 'Never Configured' }
    ) {
        $ca = New-TestCA -Property @{ AuditFilter = $Value }
        $issue = @(Find-AuditingIssue -ADCSObjects $ca -SkipRisk)
        $issue.Count | Should -Be 1
        $issue[0].Technique | Should -Be 'DETECT'
    }

    It 'Should report nothing when auditing is fully enabled' {
        @(Find-AuditingIssue -ADCSObjects (New-TestCA) -SkipRisk).Count | Should -Be 0
    }

    It 'Should not report a CA that is not Reachable, because the value is unknown' {
        @(Find-AuditingIssue -ADCSObjects (New-TestUnreachableCA) -SkipRisk).Count | Should -Be 0
    }

    It 'Should not report a CA whose AuditFilter read failed' {
        $ca = New-TestCA -Property @{ AuditFilter = $null; CAReadFailure = @{ AuditFilter = 'Access denied (0x80070005)' } }
        @(Find-AuditingIssue -ADCSObjects $ca -SkipRisk).Count | Should -Be 0
    }
}

Describe 'Find-ESC6' -Skip:(-not $adAvailable) {
    It 'Should report a CA with the flag enabled' {
        $issue = @(Find-ESC6 -ADCSObjects (New-TestCA -Property @{ SANFlag = 'Yes' }) -UnsafeUsers $unsafeUsers -SkipRisk)
        $issue.Count | Should -Be 1
        $issue[0].Technique | Should -Be 'ESC6'
    }

    It 'Should report nothing when the flag is disabled' {
        @(Find-ESC6 -ADCSObjects (New-TestCA -Property @{ SANFlag = 'No' }) -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
    }

    It 'Should not report a CA that is not Reachable, because the value is unknown' {
        @(Find-ESC6 -ADCSObjects (New-TestUnreachableCA) -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
    }
}

Describe 'Find-ESC11' -Skip:(-not $adAvailable) {
    It 'Should report a CA with the flag disabled' {
        $issue = @(Find-ESC11 -ADCSObjects (New-TestCA -Property @{ InterfaceFlag = 'No' }) -UnsafeUsers $unsafeUsers -SkipRisk)
        $issue.Count | Should -Be 1
        $issue[0].Technique | Should -Be 'ESC11'
    }

    It 'Should report nothing when the flag is enabled' {
        @(Find-ESC11 -ADCSObjects (New-TestCA -Property @{ InterfaceFlag = 'Yes' }) -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
    }

    It 'Should not report a CA that is not Reachable, because the value is unknown' {
        @(Find-ESC11 -ADCSObjects (New-TestUnreachableCA) -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
    }
}

Describe 'Find-ESC16' -Skip:(-not $adAvailable) {
    It 'Should report a CA with the extension disabled' {
        $issue = @(Find-ESC16 -ADCSObjects (New-TestCA -Property @{ DisableExtensionList = 'Yes' }) -UnsafeUsers $unsafeUsers -SkipRisk)
        $issue.Count | Should -Be 1
        $issue[0].Technique | Should -Be 'ESC16'
    }

    It 'Should report nothing when the extension is not disabled' {
        @(Find-ESC16 -ADCSObjects (New-TestCA -Property @{ DisableExtensionList = 'No' }) -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
    }

    It 'Should not report a CA that is not Reachable, because the value is unknown' {
        @(Find-ESC16 -ADCSObjects (New-TestUnreachableCA) -UnsafeUsers $unsafeUsers -SkipRisk).Count | Should -Be 0
    }
}

Describe 'Find-ESC7' -Skip:(-not $adAvailable) {
    BeforeAll {
        Mock Convert-IdentityReferenceToSid { 'S-1-5-21-1-2-3-1001' }
    }

    It 'Should report a CA Administrator and a Certificate Manager that are not safe' {
        $ca = New-TestCA -Property @{ CAAdministrator = @('CORP\Evil'); CertificateManager = @('CORP\Evil') }
        $issue = @(Find-ESC7 -ADCSObjects $ca -UnsafeUsers $unsafeUsers -SafeUsers $safeUsers -SkipRisk)
        $issue.Count | Should -Be 2
        $issue.Technique | Should -Not -Contain 'AVAILABILITY'
    }

    It 'Should skip a CA whose principal lists are null, without an error' {
        { Find-ESC7 -ADCSObjects (New-TestUnreachableCA) -UnsafeUsers $unsafeUsers -SafeUsers $safeUsers -SkipRisk -ErrorAction Stop } | Should -Not -Throw
        @(Find-ESC7 -ADCSObjects (New-TestUnreachableCA) -UnsafeUsers $unsafeUsers -SafeUsers $safeUsers -SkipRisk).Count | Should -Be 0
    }

    It 'Should never rate a principal that does not exist, which was the crash from issue 228' {
        Mock Set-RiskRating { }
        $null = Find-ESC7 -ADCSObjects (New-TestUnreachableCA) -UnsafeUsers $unsafeUsers -SafeUsers $safeUsers
        Should -Invoke Set-RiskRating -Exactly 0
        Should -Invoke Convert-IdentityReferenceToSid -Exactly 0
    }
}
