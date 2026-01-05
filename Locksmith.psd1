@{
    AliasesToExport      = @()
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2022 - 2026. All rights reserved.'
    Description          = 'A small tool to find and fix common misconfigurations in Active Directory Certificate Services.'
    FunctionsToExport    = 'Invoke-Locksmith'
    GUID                 = 'b1325b42-8dc4-4f17-aa1f-dcb5984ca14a'
    HelpInfoURI          = 'https://raw.githubusercontent.com/jakehildreth/Locksmith/main/en-US/'
    ModuleVersion        = '2026.1.4.1426'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'CimCmdlets', 'Dism')
            IconUri                    = 'https://raw.githubusercontent.com/jakehildreth/Locksmith/main/Images/locksmith.ico'
            ProjectUri                 = 'https://github.com/jakehildreth/Locksmith'
            RequireLicenseAcceptance   = $false
            Tags                       = @('Locksmith', 'ActiveDirectory', 'ADCS', 'CA', 'Certificate', 'CertificateAuthority', 'CertificateServices', 'PKI', 'X509', 'Windows')
        }
    }
    RequiredModules      = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'CimCmdlets', 'Dism')
    RootModule           = 'Locksmith.psm1'
}