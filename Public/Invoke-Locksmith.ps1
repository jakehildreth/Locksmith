function Invoke-Locksmith {
    <#
    .SYNOPSIS
    Finds the most common malconfigurations of Active Directory Certificate Services (AD CS).

    .DESCRIPTION
    Locksmith uses the Active Directory (AD) Powershell (PS) module to identify 10 misconfigurations
    commonly found in Enterprise mode AD CS installations.

    .COMPONENT
    Locksmith requires the AD PS module to be installed in the scope of the Current User.
    If Locksmith does not identify the AD PS module as installed, it will attempt to
    install the module. If module installation does not complete successfully,
    Locksmith will fail.

    .PARAMETER Mode
    Specifies sets of common script execution modes.

    -Mode 0
    Finds any malconfigurations and displays them in the console.
    No attempt is made to fix identified issues.

    -Mode 1
    Finds any malconfigurations and displays them in the console.
    Displays example Powershell snippet that can be used to resolve the issue.
    No attempt is made to fix identified issues.

    -Mode 2
    Finds any malconfigurations and writes them to a series of CSV files.
    No attempt is made to fix identified issues.

    -Mode 3
    Finds any malconfigurations and writes them to a series of CSV files.
    Creates code snippets to fix each issue and writes them to an environment-specific custom .PS1 file.
    No attempt is made to fix identified issues.

    -Mode 4
    Finds any malconfigurations and creates code snippets to fix each issue.
    Attempts to fix all identified issues. This mode may require high-privileged access.

    .PARAMETER Scans
    Specify which scans you want to run. Available scans: 'All' or Auditing, ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC8, or 'PromptMe'

    -Scans All
    Run all scans (default).

    -Scans PromptMe
    Presents a grid view of the available scan types that can be selected and run them after you click OK.

    .PARAMETER OutputPath
    Specify the path where you want to save reports and mitigation scripts.

    .INPUTS
    None. You cannot pipe objects to Invoke-Locksmith.ps1.

    .OUTPUTS
    Output types:
    1. Console display of identified issues.
    2. Console display of identified issues and their fixes.
    3. CSV containing all identified issues.
    4. CSV containing all identified issues and their fixes.

    .EXAMPLE
    Invoke-Locksmith -Mode 0 -Scans All -OutputPath 'C:\Temp'

    Finds all malconfigurations and displays them in the console.

    .EXAMPLE
    Invoke-Locksmith -Mode 2 -Scans All -OutputPath 'C:\Temp'

    Finds all malconfigurations and displays them in the console. The findings are saved in a CSV file in C:\Temp.

    .NOTES
    The Windows PowerShell cmdlet Restart-Service requires RunAsAdministrator.
    #>

    [CmdletBinding(HelpUri = 'https://jakehildreth.github.io/Locksmith/Invoke-Locksmith')]
    param (
        #[string]$Forest, # Not used yet
        #[string]$InputPath, # Not used yet

        # The mode to run Locksmith in. Defaults to 0.
        [Parameter()]
        [ValidateSet(0, 1, 2, 3, 4)]
        [int]$Mode = 0,

        # The scans to run. Defaults to 'All'.
        [Parameter()]
        [ValidateSet('Auditing',
            'ESC1',
            'ESC2',
            'ESC3',
            'ESC4',
            'ESC5',
            'ESC6',
            'ESC7',
            'ESC8',
            'ESC9',
            'ESC11',
            'ESC13',
            'ESC15',
            'EKUwu',
            'ESC16',
            'ESC17',
            'All',
            'PromptMe'
        )]
        [array]$Scans = 'All',

        # The directory to save the output in (defaults to the current working directory).
        [Parameter()]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]$OutputPath = $PWD,

        # The credential to use for working with ADCS.
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    $Version = '<ModuleVersion>'
    $LogoPart1 = @'
    _       _____  _______ _     _ _______ _______ _____ _______ _     _
    |      |     | |       |____/  |______ |  |  |   |      |    |_____|
    |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
'@
    $LogoPart2 = @'
        .--.                  .--.                  .--.
       /.-. '----------.     /.-. '----------.     /.-. '----------.
       \'-' .---'-''-'-'     \'-' .--'--''-'-'     \'-' .--'--'-''-'
        '--'                  '--'                  '--'
'@
    $VersionBanner = "                                                          v$Version"

    Write-Host $LogoPart1 -ForegroundColor Magenta
    Write-Host $LogoPart2 -ForegroundColor White
    Write-Host $VersionBanner -ForegroundColor Red

    # Check if ActiveDirectory PowerShell module is available, and attempt to install if not found
    $RSATInstalled = Test-IsRSATInstalled
    if ($RSATInstalled) {
        # Continue
    } else {
        Install-RSATADPowerShell
    }

    # Exit if running in restricted admin mode without explicit credentials
    if (!$Credential -and (Get-RestrictedAdminModeSetting)) {
        Write-Warning "Restricted Admin Mode appears to be in place, re-run with the '-Credential domain\user' option"
        break
    }

    ### Initial variables
    # For output filenames
    [string]$FilePrefix = "Locksmith $(Get-Date -Format 'yyyy-MM-dd hh-mm-ss')"

    # Extended Key Usages for client authentication. A requirement for ESC1, ESC3 Condition 2, and ESC13
    $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'

    # Extended Key Usages for server authentication. A requirement for ESC17
    $ServerAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.1'

    # GenericAll, WriteDacl, and WriteOwner all permit full control of an AD object.
    # WriteProperty may or may not permit full control depending the specific property and AD object type.
    $DangerousRights = 'GenericAll|Write'

    # Extended Key Usage for client authentication. A requirement for ESC3.
    $EnrollmentAgentEKU = '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'

    # The well-known GUIDs for Enroll and AutoEnroll rights on AD CS templates.
    $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    <#
        -519$ = Enterprise Admins group
    #>
    $SafeOwners = '-519$'

    <#
        -512$    = Domain Admins group
        -519$    = Enterprise Admins group
        -544$    = Administrators group
        -18$     = SYSTEM
        -517$    = Cert Publishers
        -500$    = Built-in Administrator
        -516$    = Domain Controllers
        -521$    = Read-Only Domain Controllers
        -9$      = Enterprise Domain Controllers
        -498$    = Enterprise Read-Only Domain Controllers
        -526$    = Key Admins
        -527$    = Enterprise Key Admins
        S-1-5-10 = SELF
    #>
    $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'

    <#
        S-1-0-0      = NULL SID
        S-1-1-0      = Everyone
        S-1-5-7      = Anonymous Logon
        S-1-5-32-545 = BUILTIN\Users
        S-1-5-11     = Authenticated Users
        -513$        = Domain Users
        -515$        = Domain Computers
    #>
    $UnsafeUsers = 'S-1-0-0|S-1-1-0|S-1-5-7|S-1-5-32-545|S-1-5-11|-513$|-515$'

    ### Generated variables
    # $Dictionary = New-Dictionary

    $Forest = Get-ADForest
    $ForestGC = $(Get-ADDomainController -Discover -Service GlobalCatalog -ForceDiscover | Select-Object -ExpandProperty Hostname) + ':3268'
    # $DNSRoot = [string]($Forest.RootDomain | Get-ADDomain).DNSRoot
    $EnterpriseAdminsSID = ([string]($Forest.RootDomain | Get-ADDomain).DomainSID) + '-519'
    $PreferredOwner = [System.Security.Principal.SecurityIdentifier]::New($EnterpriseAdminsSID)
    # $DomainSIDs = $Forest.Domains | ForEach-Object { (Get-ADDomain $_).DomainSID.Value }

    # Add SIDs of (probably) Safe Users to $SafeUsers
    Get-ADGroupMember $EnterpriseAdminsSID | ForEach-Object {
        $SafeUsers += '|' + $_.SID.Value
    }

    $Forest.Domains | ForEach-Object {
        $DomainSID = (Get-ADDomain $_).DomainSID.Value
        <#
            -517 = Cert Publishers
            -512 = Domain Admins group
        #>
        $SafeGroupRIDs = @('-517', '-512')

        # Administrators group
        $SafeGroupSIDs = @('S-1-5-32-544')
        foreach ($rid in $SafeGroupRIDs ) {
            $SafeGroupSIDs += $DomainSID + $rid
        }
        foreach ($sid in $SafeGroupSIDs) {
            $users += (Get-ADGroupMember $sid -Server $_ -Recursive).SID.Value
        }
        foreach ($user in $users) {
            $SafeUsers += '|' + $user
        }
    }
    $SafeUsers = $SafeUsers.Replace('||', '|')

    if ($Credential) {
        $Targets = Get-Target -Credential $Credential
    } else {
        $Targets = Get-Target
    }

    Write-Host "Gathering AD CS Objects from $($Targets)..."
    if ($Credential) {
        $ADCSObjects = Get-ADCSObject -Targets $Targets -Credential $Credential
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -Credential $Credential -ForestGC $ForestGC
        $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential -ForestGC $ForestGC
        $ADCSObjects += $CAHosts
    } else {
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -ForestGC $ForestGC
        $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects -ForestGC $ForestGC
        $ADCSObjects += $CAHosts
    }

    Set-AdditionalTemplateProperty -ADCSObjects $ADCSObjects

    # Add SIDs of CA Hosts to $SafeUsers
    $CAHosts | ForEach-Object { $SafeUsers += '|' + $_.objectSid }

    #if ( $Scans ) {
    # If the Scans parameter was used, Invoke-Scans with the specified checks.
    $ScansParameters = @{
        ADCSObjects        = $ADCSObjects
        ClientAuthEkus     = $ClientAuthEKUs
        ServerAuthEKUs     = $ServerAuthEKUs
        DangerousRights    = $DangerousRights
        EnrollmentAgentEKU = $EnrollmentAgentEKU
        Mode               = $Mode
        SafeObjectTypes    = $SafeObjectTypes
        SafeOwners         = $SafeOwners
        SafeUsers          = $SafeUsers
        Scans              = $Scans
        UnsafeUsers        = $UnsafeUsers
        PreferredOwner     = $PreferredOwner
    }
    $Results = Invoke-Scans @ScansParameters
    # Re-hydrate the findings arrays from the Results hash table
    $AllIssues = $Results['AllIssues']
    $AuditingIssues = $Results['AuditingIssues']
    $ESC1 = $Results['ESC1']
    $ESC2 = $Results['ESC2']
    $ESC3 = $Results['ESC3']
    $ESC4 = $Results['ESC4']
    $ESC5 = $Results['ESC5']
    $ESC6 = $Results['ESC6']
    $ESC7 = $Results['ESC7']
    $ESC8 = $Results['ESC8']
    $ESC9 = $Results['ESC9']
    $ESC11 = $Results['ESC11']
    $ESC13 = $Results['ESC13']
    $ESC15 = $Results['ESC15']
    $ESC16 = $Results['ESC16']
    $ESC17 = $Results['ESC17']

    # If these are all empty = no issues found, exit
    if ($null -eq $Results) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found.`n" -ForegroundColor Green
        Write-Host 'Thank you for using ' -NoNewline
        Write-Host "❤ Locksmith ❤ `n" -ForegroundColor Magenta
        break
    }

    switch ($Mode) {
        0 {
            Format-Result -Issue $AuditingIssues -Mode 0
            Format-Result -Issue $ESC1 -Mode 0
            Format-Result -Issue $ESC2 -Mode 0
            Format-Result -Issue $ESC3 -Mode 0
            Format-Result -Issue $ESC4 -Mode 0
            Format-Result -Issue $ESC5 -Mode 0
            Format-Result -Issue $ESC6 -Mode 0
            Format-Result -Issue $ESC7 -Mode 0
            Format-Result -Issue $ESC8 -Mode 0
            Format-Result -Issue $ESC9 -Mode 0
            Format-Result -Issue $ESC11 -Mode 0
            Format-Result -Issue $ESC13 -Mode 0
            Format-Result -Issue $ESC15 -Mode 0
            Format-Result -Issue $ESC16 -Mode 0
            Format-Result -Issue $ESC17 -Mode 0
            Write-Host @"
[!] You ran Locksmith in Mode 0 which only provides an high-level overview of issues
identified in the environment. For more details including:

  - Detailed Risk Rating
  - General remediation guidance and/or code for all issues
  - Custom remediation guidance and/or code for some issues!
  - Revert guidance and/or code (in case remediation breaks something!)
  - Distinguished Name of impacted object(s)

Try Mode 1!

# Module version
Invoke-Locksmith -Mode 1

# Script version
.\Invoke-Locksmith.ps1 -Mode 1`n
"@ -ForegroundColor Yellow
        }
        1 {
            Format-Result -Issue $AuditingIssues -Mode 1
            Format-Result -Issue $ESC1 -Mode 1
            Format-Result -Issue $ESC2 -Mode 1
            Format-Result -Issue $ESC3 -Mode 1
            Format-Result -Issue $ESC4 -Mode 1
            Format-Result -Issue $ESC5 -Mode 1
            Format-Result -Issue $ESC6 -Mode 1
            Format-Result -Issue $ESC7 -Mode 1
            Format-Result -Issue $ESC8 -Mode 1
            Format-Result -Issue $ESC9 -Mode 1
            Format-Result -Issue $ESC11 -Mode 1
            Format-Result -Issue $ESC13 -Mode 1
            Format-Result -Issue $ESC15 -Mode 1
            Format-Result -Issue $ESC16 -Mode 1
            Format-Result -Issue $ESC17 -Mode 1
        }
        2 {
            $Output = Join-Path -Path $OutputPath -ChildPath "$FilePrefix ADCSIssues.CSV"
            Write-Host "Writing AD CS issues to $Output..."
            try {
                $AllIssues | Select-Object Forest, Technique, Name, Issue, @{l = 'Risk'; e = { $_.RiskName } } | Export-Csv -NoTypeInformation $Output
                Write-Host "$Output created successfully!`n"
            } catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        3 {
            $Output = Join-Path -Path $OutputPath -ChildPath "$FilePrefix ADCSRemediation.CSV"
            Write-Host "Writing AD CS issues to $Output..."
            try {
                $AllIssues | Select-Object Forest, Technique, Name, DistinguishedName, Issue, Fix, @{l = 'Risk'; e = { $_.RiskName } }, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } | Export-Csv -NoTypeInformation $Output
                Write-Host "$Output created successfully!`n"
            } catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        4 {
            $params = @{
                AuditingIssues = $AuditingIssues
                ESC1           = $ESC1
                ESC2           = $ESC2
                ESC3           = $ESC3
                ESC4           = $ESC4
                ESC5           = $ESC5
                ESC6           = $ESC6
                ESC11          = $ESC11
                ESC13          = $ESC13
            }
            Invoke-Remediation @params
        }
    }
    Write-Host 'Thank you for using ' -NoNewline
    Write-Host 'Locksmith <3 ' -ForegroundColor Magenta -NoNewline
    Write-Host "(https://github.com/jakehildreth/Locksmith)`n"
}
