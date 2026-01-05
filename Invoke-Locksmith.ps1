[CmdletBinding(HelpUri = 'https://jakehildreth.github.io/Locksmith/Invoke-Locksmith')]
param (
    # The mode to run Locksmith in. Defaults to 0.
    [Parameter(Mandatory = $false)]
    [ValidateSet(0, 1, 2, 3, 4)]
    [int]$Mode = 0,

    # The scans to run. Defaults to 'All'.
    [Parameter()]
    [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'EKUwu', 'ESC16', 'ESC17', 'All', 'PromptMe')]
    [array]$Scans = 'All',

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Container })]
    [string]$OutputPath = $PWD
)
function Convert-IdentityReferenceToSid {
    <#
    .SYNOPSIS
        Converts an identity reference to a security identifier (SID).

    .DESCRIPTION
        The ConvertFrom-IdentityReference function takes an identity reference as input and
        converts it to a security identifier (SID). It supports both SID strings and NTAccount objects.

    .PARAMETER Object
        Specifies the identity reference to be converted. This parameter is mandatory.

    .EXAMPLE
        $object = "S-1-5-21-3623811015-3361044348-30300820-1013"
        ConvertFrom-IdentityReference -Object $object
        # Returns "S-1-5-21-3623811015-3361044348-30300820-1013"

    .EXAMPLE
        $object = New-Object System.Security.Principal.NTAccount("DOMAIN\User")
        ConvertFrom-IdentityReference -Object $object
        # Returns "S-1-5-21-3623811015-3361044348-30300820-1013"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Object
    )

    $Principal = New-Object System.Security.Principal.NTAccount($Object)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    }
    else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    return $SID
}

function Export-RevertScript {
    <#
    .SYNOPSIS
        Creates a script that reverts the changes performed by Locksmith.

    .DESCRIPTION
        This script is used to revert changes performed by Locksmith.
        It takes in various arrays of objects representing auditing issues and ESC misconfigurations.
        It creates a new script called 'Invoke-RevertLocksmith.ps1' and adds the necessary commands
        to revert the changes made by Locksmith.

    .PARAMETER AuditingIssues
        An array of auditing issues to be reverted.

    .PARAMETER ESC1
        An array of ESC1 changes to be reverted.

    .PARAMETER ESC2
        An array of ESC2 changes to be reverted.

    .PARAMETER ESC3
        An array of ESC3 changes to be reverted.

    .PARAMETER ESC4
        An array of ESC4 changes to be reverted.

    .PARAMETER ESC5
        An array of ESC5 changes to be reverted.

    .PARAMETER ESC6
        An array of ESC6 changes to be reverted.

    .PARAMETER ESC11
        An array of ESC11 changes to be reverted.

    .PARAMETER ESC13
        An array of ESC13 changes to be reverted.

    .EXAMPLE
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
        Export-RevertScript @params
        Reverts the changes performed by Locksmith using the specified arrays of objects.
    #>

    [CmdletBinding()]
    param(
        [array]$AuditingIssues,
        [array]$ESC1,
        [array]$ESC2,
        [array]$ESC3,
        [array]$ESC4,
        [array]$ESC5,
        [array]$ESC6,
        [array]$ESC11,
        [array]$ESC13
    )
    begin {
        $Output = 'Invoke-RevertLocksmith.ps1'
        $RevertScript = [System.Text.StringBuilder]::New()
        [void]$RevertScript.Append("<#`nScript to revert changes performed by Locksmith`nCreated $(Get-Date)`n#>`n")
        $Objects = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC11 + $ESC13
    }
    process {
        if ($Objects) {
            $Objects | ForEach-Object {
                [void]$RevertScript.Append("$($_.Revert)`n")
            }
            $RevertScript.ToString() | Out-File -FilePath $Output
        }
    }
}

function Find-AuditingIssue {
    <#
    .SYNOPSIS
        A function to find auditing issues on AD CS CAs.

    .DESCRIPTION
        This script takes an array of AD CS objects and filters them based on specific criteria to identify auditing issues.
        It checks if the object's objectClass is 'pKIEnrollmentService' and if the AuditFilter is not equal to '127'.
        For each matching object, it creates a custom object with information about the issue, fix, and revert actions.

    .PARAMETER ADCSObjects
        Specifies an array of ADCS objects to be checked for auditing issues.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        A custom object is created for each ADCS object that matches the criteria, containing the following properties:
        - Forest: The forest name of the object.
        - Name: The name of the object.
        - DistinguishedName: The distinguished name of the object.
        - Technique: The technique used to detect the issue (always 'DETECT').
        - Issue: The description of the auditing issue.
        - Fix: The command to fix the auditing issue.
        - Revert: The command to revert the auditing issue.

    .EXAMPLE
        $ADCSObjects = Get-ADObject -Filter * -SearchBase 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
        $AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
        $AuditingIssues
        This example retrieves ADCS objects from the specified search base and passes them to the Find-AuditingIssue function.
        It then returns the auditing issues for later use.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [switch]$SkipRisk
    )

    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKIEnrollmentService') -and
        ($_.AuditFilter -ne '127')
    } | ForEach-Object {
        $Issue = [pscustomobject]@{
            Forest            = $_.CanonicalName.split('/')[0]
            Name              = $_.Name
            DistinguishedName = $_.DistinguishedName
            Technique         = 'DETECT'
            Issue             = "Auditing is not fully enabled on $($_.CAFullName). Important security events may go unnoticed."
            Fix               = @"
certutil.exe -config '$($_.CAFullname)' -setreg CA\AuditFilter 127
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name 'certsvc' | Restart-Service -Force
}
"@
            Revert            = @"
certutil.exe -config '$($_.CAFullname)' -setreg CA\AuditFilter $($_.AuditFilter)
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name 'certsvc' | Restart-Service -Force
}
"@
        }
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue.Issue = $_.AuditFilter
            $Issue.Fix = 'N/A'
            $Issue.Revert = 'N/A'
        }
        if ($SkipRisk -eq $false) {
            Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        $Issue
    }
}

function Find-ESC1 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC1 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER ClientAuthEKUs
        A list of EKUs that can be used for client authentication.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
        $Results = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEKUs
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        $ClientAuthEKUs,
        [Parameter(Mandatory)]
        [int]$Mode,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
        ($_.'msPKI-Certificate-Name-Flag' -band 1) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
$($entry.IdentityReference) can provide a Subject Alternative Name (SAN) while
enrolling in this Client Authentication template, and enrollment does not require
Manager Approval.

The resultant certificate can be used by an attacker to authenticate as any
principal listed in the SAN up to and including Domain Admins, Enterprise Admins,
or Domain Controllers.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                    Fix                   = @"
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC1'
                }

                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }

                if ( $Mode -in @(1, 3, 4) ) {
                    Update-ESC1Remediation -Issue $Issue
                }

                $Issue
            }
        }
    }
}

function Find-ESC11 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC11 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService' and the InterfaceFlag set to 'No'. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique,
        Issue, Fix, and Revert.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Target (Get-Target)
        Find-ESC11 -ADCSObjects $ADCSObjects
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    process {
        $ADCSObjects | Where-Object {
            ($_.objectClass -eq 'pKIEnrollmentService') -and
            ($_.InterfaceFlag -ne 'Yes')
        } | ForEach-Object {
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Technique         = 'ESC11'
                Issue             = $_.InterfaceFlag
                Fix               = 'N/A'
                Revert            = 'N/A'
            }
            if ($_.InterfaceFlag -eq 'No') {
                $Issue.Issue = @'
The IF_ENFORCEENCRYPTICERTREQUEST flag is disabled on this Certification
Authority (CA). It is possible to relay NTLM authentication to the RPC interface
of this CA.

If the LAN Manager authentication level of any domain in this forest is 2 or
less, an attacker can coerce authentication from a Domain Controller (DC) to
receive a certificate which can be used to authenticate as that DC.

More info:
  - https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/

'@
                $Issue.Fix = @"
# Enable the flag
certutil -config '$CAFullname' -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
                $Issue.Revert = @"
# Disable the flag
certutil -config '$CAFullname' -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
            }
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
            $Issue
        }
    }
}

function Find-ESC13 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC13 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER ClientAuthEKUs
        A list of EKUs that can be used for client authentication.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
        $Results = $ADCSObjects | Find-ESC13 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEKUs
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$ClientAuthEKUs,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )

    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
        ($_.'msPKI-Certificate-Policy')
    } | ForEach-Object {
        foreach ($policy in $_.'msPKI-Certificate-Policy') {
            if ($ADCSObjects.'msPKI-Cert-Template-OID' -contains $policy) {
                $OidToCheck = $ADCSObjects | Where-Object 'msPKI-Cert-Template-OID' -EQ $policy
                if ($OidToCheck.'msDS-OIDToGroupLink') {
                    foreach ($entry in $_.nTSecurityDescriptor.Access) {
                        $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
                        if ($Principal -match '^(S-1|O:)') {
                            $SID = $Principal
                        }
                        else {
                            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
                        }
                        if (
                            ($SID -notmatch $SafeUsers) -and
                            ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                                ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                            ($entry.ActiveDirectoryRights -match 'GenericAll') )
                        ) {
                            $Issue = [pscustomobject]@{
                                Forest                = $_.CanonicalName.split('/')[0]
                                Name                  = $_.Name
                                DistinguishedName     = $_.DistinguishedName
                                IdentityReference     = $entry.IdentityReference
                                IdentityReferenceSID  = $SID
                                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                                Enabled               = $_.Enabled
                                EnabledOn             = $_.EnabledOn
                                LinkedGroup           = $OidToCheck.'msDS-OIDToGroupLink'
                                Issue                 = @"
$($entry.IdentityReference) can enroll in this Client Authentication template
which is linked to the group $($OidToCheck.'msDS-OIDToGroupLink').

If $($entry.IdentityReference) uses this certificate for authentication, they
will gain the rights of the linked group while the group membership appears empty.

More info:
  - https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53

"@
                                Fix                   = @"
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                                Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                                Technique             = 'ESC13'
                            }
                            if ($SkipRisk -eq $false) {
                                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                            }
                            $Issue
                        }
                    }
                }
            }
        }
    }
}

function Find-ESC15 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC15/EUKwu vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObjects -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $Results = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUser $SafeUsers
        $Results
    #>
    [alias('Find-EKUwu')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.'msPKI-Template-Schema-Version' -eq 1) -and
        ($_.Enabled)
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
$($_.Name) uses AD CS Template Schema Version 1, and $($entry.IdentityReference)
is allowed to enroll in this template.

If patches for CVE-2024-49019 have not been applied it may be possible to include
arbitrary Application Policies while enrolling in this template, including
Application Policies that permit Client Authentication or allow the creation
of Subordinate CAs.

More info:
  - https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019

"@
                    Fix                   = @"
<#
    Option 1: Manual Remediation
    Step 1: Identify if this template is Enabled on any CA.
    Step 2: If Enabled, identify if this template has recently been used to generate a certificate.
    Step 3a: If recently used, either restrict enrollment scope or convert to the template to Schema V2.
    Step 3b: If not recently used, unpublish the template from all CAs.
#>

<#
    Option 2: Scripted Remediation
    Step 1: Open an elevated Powershell session as an AD or PKI Admin
    Step 2: Run Unpublish-SchemaV1Templates.ps1
#>
Invoke-WebRequest -Uri https://gist.githubusercontent.com/jakehildreth/13c7d615adc905d317fc4379026ad28e/raw/Unpublish-SchemaV1Templates.ps1 | Invoke-Expression

"@
                    Revert                = '[TODO]'
                    Technique             = 'ESC15/EKUwu'
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}

function Find-ESC16 {
    <#
    .SYNOPSIS
        This script finds Active Directory Certificate Services (AD CS) Certification Authorities (CA) that have the ESC16 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService' and the szOID_NTDS_CA_SECURITY_EXT disabled. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique,
        Issue, Fix, and Revert.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    process {
        $ADCSObjects | Where-Object {
            ($_.objectClass -eq 'pKIEnrollmentService') -and
            ($_.DisableExtensionList -ne 'No')
        } | ForEach-Object {
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Issue             = $_.DisableExtensionList
                Fix               = 'N/A'
                Revert            = 'N/A'
                Technique         = 'ESC16'
            }
            if ($_.DisableExtensionList -eq 'Yes') {
                $Issue.Issue = @"
The Certification Authority (CA) $($_.CAFullName) has the szOID_NTDS_CA_SECURITY_EXT security extension disabled. When
this extension is disabled, every certificate issued by this CA will be unable to reliably map a certificate to a
user or computer account's SID for authentication.

More info:
  - https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally

"@
                $Issue.Fix = @"
# Enable the flag
# TODO

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
                $Issue.Revert = @"
# Disable the flag
TODO

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
            }
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
            $Issue
        }
    }
}

function Find-ESC17 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC1 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER ServerAuthEKUs
        A list of EKUs that can be used for server authentication.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ServerAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.1' 
        $Results = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ServerAuthEKUs
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        $ServerAuthEKUs,
        [Parameter(Mandatory)]
        [int]$Mode,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ServerAuthEKUs) -and
        ($_.'msPKI-Certificate-Name-Flag' -band 1) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
$($entry.IdentityReference) can provide a Subject Alternative Name (SAN) while
enrolling in this Server Authentication template, and enrollment does not require
Manager Approval.

The resultant certificate can be used by an attacker to impersonate servers
and perform Machine-in-the-Middle Attacks

More info:
  - https://trustedsec.com/blog/wsus-is-sus-ntlm-relay-attacks-in-plain-sight
  - https://blog.digitrace.de/2026/01/using-adcs-to-attack-https-enabled-wsus-clients/

"@
                    Fix                   = @"
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC17'
                }

                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }

                # if ( $Mode -in @(1, 3, 4) ) {
                #     Update-ESC1Remediation -Issue $Issue
                # }

                $Issue
            }
        }
    }
}

function Find-ESC2 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC2 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC2 -SafeUsers $SafeUsers
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.ObjectClass -eq 'pKICertificateTemplate') -and
        ( (!$_.pkiExtendedKeyUsage) -or ($_.pkiExtendedKeyUsage -match '2.5.29.37.0') ) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
$($entry.IdentityReference) can use this template to request any type
of certificate - including Enrollment Agent certificates and Subordinate
Certification Authority (SubCA) certificate - without Manager Approval.

If an attacker requests an Enrollment Agent certificate and there exists at least
one enabled ESC3 Condition 2 or ESC15 template available that does not require
Manager Approval, the attacker can request a certificate on behalf of another principal.
The risk presented depends on the privileges granted to the other principal.

If an attacker requests a SubCA certificate, the resultant certificate can be used
by an attacker to instantiate their own SubCA which is trusted by AD.

By default, certificates created from this attacker-controlled SubCA cannot be
used for authentication, but they can be used for other purposes such as TLS
certs and code signing.

However, if an attacker can modify the NtAuthCertificates object (see ESC5),
they can convert their rogue CA into one trusted for authentication.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                    Fix                   = @"
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC2'
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}

function Find-ESC3C1 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that match the first condition required for ESC3 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC3C1 -SafeUsers $SafeUsers
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $EnrollmentAgentEKU) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
$($entry.IdentityReference) can use this template to request an Enrollment Agent
certificate without Manager Approval.

The resulting certificate can be used to enroll in any template that allows
an Enrollment Agent to submit the request.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                    Fix                   = @"
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC3'
                    Condition             = 1
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}

function Find-ESC3C2 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that match the second condition required for ESC3 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Targets (Get-Target)
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC3C2 -SafeUsers $SafeUsers
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKU) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ($_.'msPKI-RA-Application-Policies' -match '1.3.6.1.4.1.311.20.2.1') -and
        ($_.'msPKI-RA-Signature' -eq 1)
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
If the holder of a SubCA, Any Purpose, or Enrollment Agent certificate requests
a certificate using this template, they will receive a certificate which allows
them to authenticate as $($entry.IdentityReference).

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                    Fix                   = @"
First, eliminate unused Enrollment Agent templates.
Then, tightly scope any Enrollment Agent templates that remain and:
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC3'
                    Condition             = 2
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}

function Find-ESC4 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC4 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER DangerousRights
        Specifies the list of dangerous rights that should not be assigned to users. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER SafeObjectTypes
        Specifies a list of ObjectTypes which are not a security concern. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Targets (Get-Target)

        # GenericAll, WriteDacl, and WriteOwner all permit full control of an AD object.
        # WriteProperty may or may not permit full control depending the specific property and AD object type.
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')

        # -512$ = Domain Admins group
        # -519$ = Enterprise Admins group
        # -544$ = Administrators group
        # -18$  = SYSTEM
        # -517$ = Cert Publishers
        # -500$ = Built-in Administrator
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'

        # -512$    = Domain Admins group
        # -519$    = Enterprise Admins group
        # -544$    = Administrators group
        # -18$     = SYSTEM
        # -517$    = Cert Publishers
        # -500$    = Built-in Administrator
        # -516$    = Domain Controllers
        # -521$    = Read-Only Domain Controllers
        # -9$      = Enterprise Domain Controllers
        # -526$    = Key Admins
        # -527$    = Enterprise Key Admins
        # S-1-5-10 = SELF
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'

        # The well-known GUIDs for Enroll and AutoEnroll rights on AD CS templates.
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'

        # Set output mode
        $Mode = 1

        $Results = Find-ESC4 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes -Mode $Mode
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$DangerousRights,
        [Parameter(Mandatory)]
        [string]$SafeOwners,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$SafeObjectTypes,
        [Parameter(Mandatory)]
        [int]$Mode,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object objectClass -EQ 'pKICertificateTemplate' | ForEach-Object {
        if ($_.Name -ne '' -and $null -ne $_.Name) {
            $Principal = [System.Security.Principal.NTAccount]::New($_.nTSecurityDescriptor.Owner)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
        }

        if ($SID -notmatch $SafeOwners) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $_.nTSecurityDescriptor.Owner
                IdentityReferenceSID  = $SID
                ActiveDirectoryRights = 'Owner'
                Enabled               = $_.Enabled
                EnabledOn             = $_.EnabledOn
                Issue                 = @"
$($_.nTSecurityDescriptor.Owner) has Owner rights on this template and can
modify it into a template that can create ESC1, ESC2, and ESC3 templates.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                Fix                   = @"
`$Owner = New-Object System.Security.Principal.SecurityIdentifier('$PreferredOwner')
`$ACL = Get-Acl -Path 'AD:$($_.DistinguishedName)'
`$ACL.SetOwner(`$Owner)
Set-ACL -Path 'AD:$($_.DistinguishedName)' -AclObject `$ACL
"@
                Revert                = @"
`$Owner = New-Object System.Security.Principal.SecurityIdentifier('$($_.nTSecurityDescriptor.Owner)')
`$ACL = Get-Acl -Path 'AD:$($_.DistinguishedName)'
`$ACL.SetOwner(`$Owner)
Set-ACL -Path 'AD:$($_.DistinguishedName)' -AclObject `$ACL
"@
                Technique             = 'ESC4'
            }
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
            $Issue
        }

        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            if ($_.Name -ne '' -and $null -ne $_.Name) {
                $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
                if ($Principal -match '^(S-1|O:)') {
                    $SID = $Principal
                }
                else {
                    $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
                }
            }

            if ( ($SID -notmatch $SafeUsers) -and
                ($entry.AccessControlType -eq 'Allow') -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) -and
                ($entry.ObjectType -notmatch $SafeObjectTypes)
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
$($entry.IdentityReference) has been granted $($entry.ActiveDirectoryRights) rights on this template.

$($entry.IdentityReference) can likely modify this template into an ESC1 template.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                    Fix                   = @"
`$ACL = Get-Acl -Path 'AD:$($_.DistinguishedName)'
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
Set-Acl -Path 'AD:$($_.DistinguishedName)' -AclObject `$ACL
"@
                    Revert                = '[TODO]'
                    Technique             = 'ESC4'
                }

                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }

                if ( $Mode -in @(1, 3, 4) ) {
                    Update-ESC4Remediation -Issue $Issue
                }

                $Issue
            }
        }
    }
}

function Find-ESC5 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC5 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER DangerousRights
        Specifies the list of dangerous rights that should not be assigned to users. This parameter is mandatory.

    .PARAMETER SafeOwners
        Specifies the list of SIDs of safe owners who are allowed to have owner rights on the objects. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER SafeObjectTypes
        Specifies a list of ObjectTypes that are not a security concern. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject

        # GenericAll, WriteDacl, and WriteOwner all permit full control of an AD object.
        # WriteProperty may or may not permit full control depending the specific property and AD object type.
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')

        # -512$ = Domain Admins group
        # -519$ = Enterprise Admins group
        # -544$ = Administrators group
        # -18$  = SYSTEM
        # -517$ = Cert Publishers
        # -500$ = Built-in Administrator
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'

        # -512$    = Domain Admins group
        # -519$    = Enterprise Admins group
        # -544$    = Administrators group
        # -18$     = SYSTEM
        # -517$    = Cert Publishers
        # -500$    = Built-in Administrator
        # -516$    = Domain Controllers
        # -521$    = Read-Only Domain Controllers
        # -9$      = Enterprise Domain Controllers
        # -526$    = Key Admins
        # -527$    = Enterprise Key Admins
        # S-1-5-10 = SELF
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'

        # The well-known GUIDs for Enroll and AutoEnroll rights on AD CS templates.
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $Results = $ADCSObjects | Find-ESC5 -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers  -SafeObjectTypes $SafeObjectTypes
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$DangerousRights,
        [Parameter(Mandatory)]
        [string]$SafeOwners,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$SafeObjectTypes,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | ForEach-Object {
        if ($_.Name -ne '' -and $null -ne $_.Name) {
            $Principal = New-Object System.Security.Principal.NTAccount($_.nTSecurityDescriptor.Owner)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
        }

        $IssueDetail = ''
        $DangerousOwner = $false
        if ( ($_.objectClass -eq 'computer') -and ($SID -match '-512$') ) {
            $DangerousOwner = $false
        }
        elseif ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $DangerousOwner = $true
        }

        if ($DangerousOwner) {
            switch ($_.objectClass) {
                container {
                    $IssueDetail = @"
With ownership rights, this principal can modify the container as they wish.
Depending on the exact container, this may result in the rights to create new
CA objects, new templates, new OIDs, etc. to create novel escalation paths.
"@
                }
                computer {
                    $IssueDetail = @"
This computer is hosting a Certification Authority (CA).

There is no reason for anyone other than Enterprise Admins or Domain Admins to
own CA host objects.
"@
                }
                'msPKI-Cert-Template-OID' {
                    $IssueDetail = @"
This Object Identifier (OID) can be modified into an Application Policy and linked
to an empty Universal Group.

If this principal also has ownership or control over a certificate template
(see ESC4), an attacker could link this Application Policy to the template. Once
linked, any certificates issued from that template would allow an attacker to
act as a member of the linked group (see ESC13).
"@
                }
                pKIEnrollmentService {
                    $IssueDetail = @"
Ownership rights can be used to enable currently disabled templates.

If this prinicpal also has control over a disabled certificate template (aka ESC4),
they could modify the template into an ESC1 template and enable the certificate.
This enabled certificate could be use for privilege escalation and persistence.
"@
                }
            }
            if ($_.objectClass -eq 'certificationAuthority' -and $_.Name -eq 'NTAuthCertificates') {
                $IssueDetail = @"
The NTAuthCertificates object determines which Certification Authorities are
trusted by Active Directory (AD) for client authentication of all forms.

This principal can use their granted rights on NTAuthCertificates to add their own
rogue CAs. Once the rogue CA is trusted by AD, any client authentication
certificate generated by the CA can be used by the attacker to authenticate.
"@
            }

            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $_.nTSecurityDescriptor.Owner
                IdentityReferenceSID  = $SID
                ActiveDirectoryRights = 'Owner'
                objectClass           = $_.objectClass
                Issue                 = @"
$($_.nTSecurityDescriptor.Owner) has Owner rights on this $($_.objectClass) object. They are able
to modify this object in whatever way they wish.

$IssueDetail

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                Fix                   = @"
`$Owner = New-Object System.Security.Principal.SecurityIdentifier('$PreferredOwner')
`$ACL = Get-Acl -Path 'AD:$($_.DistinguishedName)'
`$ACL.SetOwner(`$Owner)
Set-ACL -Path 'AD:$($_.DistinguishedName)' -AclObject `$ACL
"@
                Revert                = "
`$Owner = New-Object System.Security.Principal.SecurityIdentifier('$($_.nTSecurityDescriptor.Owner)')
`$ACL = Get-Acl -Path 'AD:$($_.DistinguishedName)'
`$ACL.SetOwner(`$Owner)
Set-ACL -Path 'AD:$($_.DistinguishedName)' -AclObject `$ACL"
                Technique             = 'ESC5'
            } # end switch ($_.objectClass)
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
            $Issue
        } # end if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) )

        $IssueDetail = ''
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }

            switch ($_.objectClass) {
                container {
                    $IssueDetail = @"
With these rights, this principal may be able to modify the container as they wish.
Depending on the exact container, this may result in the rights to create new
CA objects, new templates, new OIDs, etc. to create novel escalation paths.
"@
                }
                computer {
                    $IssueDetail = @"
This computer is hosting a Certification Authority (CA). It is likely
$($entry.IdentityReference) can take control of this object.

There is little reason for anyone other than AD Admins to have elevated rights
to this CA host.
"@
                }
                'msPKI-Cert-Template-OID' {
                    $IssueDetail = @"
This Object Identifier (OID) can be modified into an Application Policy and linked
to an empty Universal Group.

If $($entry.IdentityReference) also has control over a certificate template
(see ESC4), an attacker could link this Application Policy to the template. Once
linked, any certificates issued from that template would allow an attacker to
act as a member of the linked group (see ESC13).
"@
                }
                pKIEnrollmentService {
                    $IssueDetail = @"
$($entry.IdentityReference) can use these elevated rights to publish currently
disabled templates.

If $($entry.IdentityReference) also has control over a disabled certificate
template (see ESC4), they could modify the template into an ESC1 template then
enable the certificate. This enabled certificate could be use for privilege
escalation and persistence.
"@
                }
            } # end switch ($_.objectClass)
            if ($_.objectClass -eq 'certificationAuthority' -and $_.Name -eq 'NTAuthCertificates') {
                $IssueDetail = @"
The NTAuthCertificates object determines which Certification Authorities are
trusted by Active Directory (AD) for client authentication of all forms.

$($entry.IdentityReference) can use their granted rights on NTAuthCertificates
to add their own rogue CAs. Once the rogue CA is trusted, any client authentication
certificates generated by the it can be used by the attacker.
"@
            }

            if ( ($_.objectClass -ne 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.AccessControlType -eq 'Allow') -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) -and
                ($entry.ObjectType -notmatch $SafeObjectTypes) ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    objectClass           = $_.objectClass
                    Issue                 = @"
$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) elevated rights
on this $($_.objectClass) object.

$IssueDetail

"@
                    Fix                   = @"
`$ACL = Get-Acl -Path 'AD:$($_.DistinguishedName)'
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and
        ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
Set-Acl -Path 'AD:$($_.DistinguishedName)' -AclObject `$ACL
"@
                    Revert                = '[TODO]'
                    Technique             = 'ESC5'
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            } # end if ( ($_.objectClass -ne 'pKICertificateTemplate')
        } # end foreach ($entry in $_.nTSecurityDescriptor.Access)
    } # end $ADCSObjects | ForEach-Object
}

function Find-ESC6 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC6 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService' and the SANFlag set to 'Yes'. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique,
        Issue, Fix, and Revert.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Results = $ADCSObjects | Find-ESC6
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    process {
        $ADCSObjects | Where-Object {
            ($_.objectClass -eq 'pKIEnrollmentService') -and
            ($_.SANFlag -ne 'No')
        } | ForEach-Object {
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                CAFullname        = $CAFullName
                DistinguishedName = $_.DistinguishedName
                Issue             = $_.SANFlag
                Fix               = 'N/A'
                Revert            = 'N/A'
                Technique         = 'ESC6'
            }
            if ($_.SANFlag -eq 'Yes') {
                $Issue.Issue = @"
The dangerous EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled on $CAFullname.
All templates enabled on this CA will accept a Subject Alternative Name (SAN)
during enrollment even if the template is not specifically configured to allow a SAN.

As of May 2022, Microsoft has neutered this situation by requiring all SANs to
be strongly mapped to certificates.

However, if strong mapping has been explicitly disabled on Domain Controllers,
this configuration remains vulnerable to privilege escalation attacks.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2
  - https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

"@
                $Issue.Fix = @"
# Disable the flag
certutil -config '$CAFullname' -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
                $Issue.Revert = @"
# Enable the flag
certutil -config '$CAFullname' -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart the Certificate Authority service
Invoke-Command -ComputerName '$($_.dNSHostName)' -ScriptBlock {
    Get-Service -Name certsvc | Restart-Service -Force
}
"@
            }
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
            $Issue
        }
    }
}

function Find-ESC7 {
    <#
    .SYNOPSIS
        This script finds Active Directory Certificate Services (AD CS) Certificate Authorities (CA) that have the ESC7 vulnerability.

    .DESCRIPTION
        The script takes an array of AD CS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService'. If the CA objects have non-standard/unsafe principals as administrators or managers, an issue is created.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS objects to be processed. This parameter is mandatory.

    .PARAMETER UnsafeUsers
        Principals that should never be granted control of a CA.

    .PARAMETER SafeUsers
        Principals that are generally recognized as safe to control a CA.

    .PARAMETER SkipRisk
        Switch used when processing second-order risks.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching AD CS objects and their associated information.

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [switch]$SkipRisk
    )
    process {
        Write-Output $ADCSObjects -PipelineVariable object | Where-Object {
            ($object.objectClass -eq 'pKIEnrollmentService') -and $object.CAHostDistinguishedName -and
            ( ($object.CAAdministrator) -or ($object.CertificateManager) )
        } | ForEach-Object {
            Write-Output $object.CAAdministrator -PipelineVariable admin | ForEach-Object {
                $SID = Convert-IdentityReferenceToSid -Object $admin
                if ($SID -notmatch $SafeUsers) {
                    $Issue = [pscustomobject]@{
                        Forest               = $object.CanonicalName.split('/')[0]
                        Name                 = $object.Name
                        DistinguishedName    = $object.DistinguishedName
                        IdentityReference    = $admin
                        IdentityReferenceSID = $SID
                        Right                = 'CA Administrator'
                        Issue                = @"
$admin has been granted CA Administrator rights on this Certification Authority (CA).

$admin has full control over this CA.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                        Fix                  = "Revoke CA Administrator rights from ${admin}."
                        Revert               = "Restore CA Administrator rights to ${admin}."
                        Technique            = 'ESC7'
                    }

                    if ($SkipRisk -eq $false) {
                        Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                    }

                    if ( $Mode -in @(1, 3, 4) ) {
                        Update-ESC7Remediation -Issue $Issue
                    }

                    $Issue
                }
            }

            Write-Output $object.CertificateManager -PipelineVariable admin | ForEach-Object {
                $SID = Convert-IdentityReferenceToSid -Object $admin
                if ($SID -notmatch $SafeUsers) {
                    $Issue = [pscustomobject]@{
                        Forest               = $object.CanonicalName.split('/')[0]
                        Name                 = $object.Name
                        DistinguishedName    = $object.DistinguishedName
                        IdentityReference    = $admin
                        IdentityReferenceSID = $SID
                        Right                = 'Certificate Manager'
                        Issue                = @"
$admin has been granted Certificate Manager rights on this Certification Authority (CA).

$admin can approve pending certificate requests on this CA.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                        Fix                  = "Revoke Certificate Manager rights from ${admin}."
                        Revert               = "Restore Certificate Manager rights to ${admin}."
                        Technique            = 'ESC7'
                    }

                    if ($SkipRisk -eq $false) {
                        Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                    }

                    if ( $Mode -in @(1, 3, 4) ) {
                        Update-ESC7Remediation -Issue $Issue
                    }

                    $Issue
                }
            }
        }
    }
}

function Find-ESC8 {
    <#
    .SYNOPSIS
        Finds ADCS objects with enrollment endpoints and identifies the enrollment type.

    .DESCRIPTION
        This script takes an array of ADCS objects and filters them based on the presence of a CA enrollment endpoint.
        It then determines the enrollment type (HTTP or HTTPS) for each object and returns the results.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to process. This parameter is mandatory.

    .OUTPUTS
        An object representing the ADCS object with the following properties:
        - Forest: The forest name of the object.
        - Name: The name of the object.
        - DistinguishedName: The distinguished name of the object.
        - CAEnrollmentEndpoint: The CA enrollment endpoint of the object.
        - Issue: The identified issue with the enrollment type.
        - Fix: The recommended fix for the issue.
        - Revert: The recommended revert action for the issue.
        - Technique: The technique used to identify the issue.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Results = $ADCSObjects | Find-ESC8
        $Results
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )

    process {
        $ADCSObjects | Where-Object {
            $_.CAEnrollmentEndpoint
        } | ForEach-Object {
            foreach ($endpoint in $_.CAEnrollmentEndpoint) {
                $Issue = [pscustomobject]@{
                    Forest               = $_.CanonicalName.split('/')[0]
                    Name                 = $_.Name
                    DistinguishedName    = $_.DistinguishedName
                    CAEnrollmentEndpoint = $endpoint.URL
                    AuthType             = $endpoint.Auth
                    Issue                = @'
An HTTP enrollment endpoint is available. It is possible to relay NTLM
authentication to this HTTP endpoint.

If the LAN Manager authentication level of any domain in this forest is 2 or
less, an attacker can coerce authentication from a Domain Controller (DC) and
relay it to this HTTP enrollment endpoint to receive a certificate which can be
used to authenticate as that DC.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

'@
                    Fix                  = @'
Disable HTTP access and enforce HTTPS.
Enable EPA.
Disable NTLM authentication (if possible.)
'@
                    Revert               = '[TODO]'
                    Technique            = 'ESC8'
                }
                if ($endpoint.URL -match '^https:') {
                    $Issue.Issue = @'
An HTTPS enrollment endpoint is available. It may be possible to relay NTLM
authentication to this HTTPS endpoint. Enabling IIS Extended Protection for
Authentication or disabling NTLM authentication completely, NTLM relay is not
possible.

If those protection are not in place, and the LAN Manager authentication level
of any domain in this forest is 2 or less, an attacker can coerce authentication
from a Domain Controller (DC) and relay it to this HTTPS enrollment endpoint to
receive a certificate which can be used to authenticate as that DC.

'@
                    $Issue.Fix = @'
Ensure EPA is enabled.
Disable NTLM authentication (if possible.)
'@
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}

function Find-ESC9 {
    <#
    .SYNOPSIS
        This function finds Active Directory Certificate Services (AD CS)  objects that have the ESC9 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .PARAMETER UnsafeUsers
        Specifies the list of SIDs of safe users who should never have specific rights on the objects. This parameter is mandatory.

    .PARAMETER ClientAuthEKUs
        A list of EKUs that can be used for client authentication.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
        $Results = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEKUs
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        $ClientAuthEKUs,
        [int]$Mode = 0,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
        ($_.'msPKI-Enrollment-Flag' -band 0x80000)
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if (
                ($SID -notmatch $SafeUsers) -and
                ( ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -and
                    ( $entry.ObjectType -match '0e10c968-78fb-11d2-90d4-00c04f79dc55|00000000-0000-0000-0000-000000000000' ) ) -or
                ($entry.ActiveDirectoryRights -match 'GenericAll') )
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Enabled               = $_.Enabled
                    EnabledOn             = $_.EnabledOn
                    Issue                 = @"
This Client Authentication template has the szOID_NTDS_CA_SECURITY_EXT security
extension disabled. Certificates issued from this template will not enforce
strong certificate binding. Depending on the current Certificate Binding
Enforcement level ESC6 status, it may be possible to request and receive
certificates that rely on weak (aka attacker-controllable) binding methods.

An attacker can abuse this weakness by:
1. Getting access to a user or computer account.
2. Modifying the user's userPrincipalName attribute (or the computer's dNSHostName attribute) to match a higher-privileged account.
3. Requesting a client authentication certificate from a template that w/ szOID_NTDS_CA_SECURITY_EXT disabled.
4. Using the client authentication certificiate to authenticate as the higher-privileged account.
5. Profiting.

More info:
  - ESC9 description: https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template
  - Strong Mapping/Enforcement Mode: https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

"@
                    Fix                   = @"
# Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC9'
                }

                if ( $Mode -in @(1, 3, 4) ) {
                    Update-ESC9Remediation -Issue $Issue
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            }
        }
    }
}

function Format-Result {
    <#
    .SYNOPSIS
        Formats the result of an issue for display.

    .DESCRIPTION
        This script formats the result of an issue for display based on the specified mode.

    .PARAMETER Issue
        The issue object containing information about the detected issue.

    .PARAMETER Mode
        The mode to determine the formatting style. Valid values are 0 and 1.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 0
        Formats the issue result in table format.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 1
        Formats the issue result in list format.

    .NOTES
        Authors: Spencer Alessi & Jake Hildreth
    #>
    [CmdletBinding()]
    param(
        $Issue,
        [Parameter(Mandatory)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT        = 'Auditing Not Fully Enabled'
        ESC1          = 'ESC1 - Vulnerable Certificate Template - Client Authentication'
        ESC2          = 'ESC2 - Vulnerable Certificate Template - Subordinate CA/Any Purpose'
        ESC3          = 'ESC3 - Vulnerable Certificate Template - Enrollment Agent'
        ESC4          = 'ESC4 - Vulnerable Access Control - Certificate Template'
        ESC5          = 'ESC5 - Vulnerable Access Control - PKI Object'
        ESC6          = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled'
        ESC7          = 'ESC7 - Non-standard PKI Admins'
        ESC8          = 'ESC8 - HTTP/S Enrollment Enabled'
        ESC9          = 'ESC9 - szOID_NTDS_CA_SECURITY_EXT Extension Disabled on Template'
        ESC11         = 'ESC11 - IF_ENFORCEENCRYPTICERTREQUEST Flag Disabled'
        ESC13         = 'ESC13 - Vulnerable Certificate Template - Group-Linked'
        'ESC15/EKUwu' = 'ESC15 - Vulnerable Certificate Template - Schema V1'
        ESC16         = 'ESC16 - szOID_NTDS_CA_SECURITY_EXT Extension Disabled on CA'
        ESC17         = 'ESC17 - Vulnerable Certificate Template - Server Authentication'
    }

    $RiskTable = @{
        'Informational' = 'Black, White'
        'Low'           = 'Black, Yellow'
        'Medium'        = 'Black, DarkYellow'
        'High'          = 'Black, Red'
        'Critical'      = 'White, DarkRed'
    }

    if ($null -ne $Issue) {
        $UniqueIssue = $Issue.Technique | Sort-Object -Unique
        $Title = $($IssueTable[$UniqueIssue])
        Write-Host "$('-'*($($Title.ToString().Length + 10)))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
        Write-Host "     " -BackgroundColor Magenta -NoNewline
        Write-Host $Title -BackgroundColor Magenta -ForegroundColor Black -NoNewline
        Write-Host "     " -BackgroundColor Magenta -NoNewline; Write-Host
        Write-Host "$('-'*($($Title.ToString().Length + 10)))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host


        if ($Mode -eq 0) {
            # TODO Refactor this
            switch ($UniqueIssue) {
                { $_ -in @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC16') } {
                    $Issue |
                        Format-Table Technique, @{l = 'CA Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Issue -Wrap |
                            Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                { $_ -in @('ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC9', 'ESC13', 'ESC15/EKUwu', 'ESC17') } {
                    $Issue |
                        Format-Table Technique, @{l = 'Template Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Enabled, Issue -Wrap |
                            Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                'ESC5' {
                    $Issue |
                        Format-Table Technique, @{l = 'Object Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Issue -Wrap |
                            Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
            }
        }
        elseif ($Mode -eq 1) {
            switch ($UniqueIssue) {
                { $_ -in @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC16') } {
                    $Issue |
                        Format-List Technique, @{l = 'CA Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, DistinguishedName, Issue, Fix, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } |
                            Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                { $_ -in @('ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC9', 'ESC13', 'ESC15/EKUwu') } {
                    $Issue |
                        Format-List Technique, @{l = 'Template Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, DistinguishedName, Enabled, EnabledOn, Issue, Fix, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } |
                            Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
                'ESC5' {
                    $Issue |
                        Format-List Technique, @{l = 'Object Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, DistinguishedName, objectClass, Issue, Fix, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } |
                            Write-HostColorized -PatternColorMap $RiskTable -CaseSensitive
                }
            }
        }
    }
}

function Get-ADCSObject {
    <#
    .SYNOPSIS
        Retrieves Active Directory Certificate Services (AD CS) objects.

    .DESCRIPTION
        This script retrieves AD CS objects from the specified forests.
        It can be used to gather information about Public Key Services in Active Directory.

    .PARAMETER Targets
        Specifies the forest(s) from which to retrieve AD CS objects.

    .PARAMETER Credential
        Specifies the credentials to use for authentication when retrieving ADCS objects.

    .EXAMPLE
        Get-ADCSObject -Credential $cred -Targets (Get-Target)
        This example retrieves ADCS objects from the local forest using the specified credentials.

    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Targets,
        [System.Management.Automation.PSCredential]$Credential
    )
    foreach ( $forest in $Targets ) {
        if ($Credential) {
            $ADRoot = (Get-ADRootDSE -Credential $Credential -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties * -Credential $Credential
        }
        else {
            $ADRoot = (Get-ADRootDSE -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties *
        }
    }
}

function Get-CAHostObject {
    <#
    .SYNOPSIS
        Retrieves Certificate Authority (CA) host object(s) from Active Directory.

    .DESCRIPTION
        This script retrieves CA host object(s) associated with every CA configured in the target Active Directory forest.
        If a Credential is provided, the script retrieves the CA host object(s) using the specified credentials.
        If no Credential is provided, the script retrieves the CA host object(s) using the current credentials.

    .PARAMETER ADCSObjects
        Specifies an array of AD CS objects to retrieve the CA host object for.

    .PARAMETER Credential
        Specifies the credentials to use for retrieving the CA host object(s). If not provided, current credentials will be used.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Credential = Get-Credential
        Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential

        This example retrieves the CA host object(s) associated with every CA in the target forest using the provided credentials.

    .INPUTS
        System.Array

    .OUTPUTS
        System.Object

    #>
    [CmdletBinding()]
    param (
        [parameter(
            Mandatory,
            ValueFromPipeline = $true)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [System.Management.Automation.PSCredential]$Credential,
        $ForestGC
    )
    process {
        if ($Credential) {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                if ($_.CAHostDistinguishedName) {
                    Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC -Credential $Credential 
                }
                else {
                    Write-Warning "Get-CAHostObject: Unable to get information from $($_.DisplayName)" 
                }
            }
        }
        else {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                if ($_.CAHostDistinguishedName) {
                    Get-ADObject -Identity $_.CAHostDistinguishedName -Properties * -Server $ForestGC 
                }
                else {
                    Write-Warning "Get-CAHostObject: Unable to get information from $($_.DisplayName)" 
                }
            }
        }
    }
}

function Get-RestrictedAdminModeSetting {
    <#
    .SYNOPSIS
        Retrieves the current configuration of the Restricted Admin Mode setting.

    .DESCRIPTION
        This script retrieves the current configuration of the Restricted Admin Mode setting from the registry.
        It checks if the DisableRestrictedAdmin value is set to '0' and the DisableRestrictedAdminOutboundCreds value is set to '1'.
        If both conditions are met, it returns $true; otherwise, it returns $false.

    .PARAMETER None

    .EXAMPLE
        Get-RestrictedAdminModeSetting
        True
    #>

    $Path = 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa'
    try {
        $RAM = (Get-ItemProperty -Path $Path).DisableRestrictedAdmin
        $Creds = (Get-ItemProperty -Path $Path).DisableRestrictedAdminOutboundCreds
        if ($RAM -eq '0' -and $Creds -eq '1') {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        return $false
    }
}

function Get-Target {
    <#
    .SYNOPSIS
        Retrieves the target forest(s) based on a provided forest name, input file, or current Active Directory forest.

    .DESCRIPTION
        This script retrieves the target forest(s) based on the provided forest name, input file, or current Active Directory forest.
        If the $Forest parameter is specified, the script sets the target to the provided forest.
        If the $InputPath parameter is specified, the script reads the target forest(s) from the file specified by the input path.
        If neither $Forest nor $InputPath is specified, the script retrieves objects from the current Active Directory forest.
        If the $Credential parameter is specified, the script retrieves the target(s) using the provided credentials.

    .PARAMETER Forest
        Specifies a single forest to retrieve objects from.

    .PARAMETER InputPath
        Specifies the path to the file containing the target forest(s).

    .PARAMETER Credential
        Specifies the credentials to use for retrieving the target(s) from the Active Directory forest.

    .EXAMPLE
        Get-Target -Forest "example.com"
        Sets the target forest to "example.com".

    .EXAMPLE
        Get-Target -InputPath "C:\targets.txt"
        Retrieves the target forest(s) from the file located at "C:\targets.txt".

    .EXAMPLE
        Get-Target -Credential $cred
        Sets the target forest to the current Active Directory forest using the provided credentials.

    .OUTPUTS
        System.String
        The target(s) retrieved based on the specified parameters.

    #>

    param (
        [string]$Forest,
        [string]$InputPath,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Forest) {
        $Targets = $Forest
    }
    elseif ($InputPath) {
        $Targets = Get-Content $InputPath
    }
    else {
        if ($Credential) {
            $Targets = (Get-ADForest -Credential $Credential).Name
        }
        else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}

function Install-RSATADPowerShell {
    <#
    .SYNOPSIS
        Installs the RSAT AD PowerShell module.
    .DESCRIPTION
        This function checks if the current process is elevated and if it is it will prompt to install the RSAT AD PowerShell module.
    .EXAMPLE
        Install-RSATADPowerShell
    #>
    if (Test-IsElevated) {
        $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        # 1 - workstation, 2 - domain controller, 3 - non-dc server
        if ($OS -gt 1) {
            Write-Warning "The Active Directory PowerShell module is not installed."
            Write-Host "If you continue, Locksmith will attempt to install the Active Directory PowerShell module for you.`n" -ForegroundColor Yellow
            Write-Host "`nCOMMAND: Install-WindowsFeature -Name RSAT-AD-PowerShell`n" -ForegroundColor Cyan
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
                    Install-WindowsFeature -Name RSAT-AD-PowerShell
                }
                catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            }
            else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        }
        else {
            Write-Warning "The Active Directory PowerShell module is not installed."
            Write-Host "If you continue, Locksmith will attempt to install the Active Directory PowerShell module for you.`n" -ForegroundColor Yellow
            Write-Host "`nCOMMAND: Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online`n" -ForegroundColor Cyan
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
                    Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
                }
                catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            }
            else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        }
    }
    else {
        Write-Warning -Message "The ActiveDirectory PowerShell module is required for Locksmith, but is not installed. Please launch an elevated PowerShell session to have this module installed for you automatically."
        # The goal here is to exit the script without closing the PowerShell window. Need to test.
        return
    }
}
function Invoke-Remediation {
    <#
    .SYNOPSIS
    Runs any remediation scripts available.

    .DESCRIPTION
    This function offers to run any remediation code associated with identified issues.

    .PARAMETER AuditingIssues
    A PS Object containing all necessary information about auditing issues.

    .PARAMETER ESC1
    A PS Object containing all necessary information about ESC1 issues.

    .PARAMETER ESC2
    A PS Object containing all necessary information about ESC2 issues.

    .PARAMETER ESC3
    A PS Object containing all necessary information about ESC3 issues.

    .PARAMETER ESC4
    A PS Object containing all necessary information about ESC4 issues.

    .PARAMETER ESC5
    A PS Object containing all necessary information about ESC5 issues.

    .PARAMETER ESC6
    A PS Object containing all necessary information about ESC6 issues.

    .PARAMETER ESC11
    A PS Object containing all necessary information about ESC11 issues.

    .PARAMETER ESC13
    A PS Object containing all necessary information about ESC13 issues.

    .INPUTS
    PS Objects

    .OUTPUTS
    Console output
    #>

    [CmdletBinding()]
    param (
        $AuditingIssues,
        $ESC1,
        $ESC2,
        $ESC3,
        $ESC4,
        $ESC5,
        $ESC6,
        $ESC11,
        $ESC13
    )

    Write-Host "`nExecuting Mode 4 - Attempting to fix identified issues!`n" -ForegroundColor Green
    Write-Host 'Creating a script (' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1' -ForegroundColor White -NoNewline
    Write-Host ") which can be used to revert all changes made by Locksmith...`n"
    try {
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
        Export-RevertScript @params
    }
    catch {
        Write-Warning 'Creation of Invoke-RevertLocksmith.ps1 failed.'
        Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
        Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
        Write-Host 'No: ' -NoNewline
        $WarningError = ''
        $WarningError = Read-Host
        if ($WarningError -like 'y') {
            # Continue
        }
        else {
            break
        }
    }
    if ($AuditingIssues) {
        $AuditingIssues | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to fully enable auditing on Certification Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not modify AD CS auditing. Are you a local admin on the CA host?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC1) {
        $ESC1 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'COMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC2) {
        $ESC2 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC4) {
        $ESC4 | Where-Object Issue -Like '* Owner rights *' | ForEach-Object { # This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" template to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC5) {
        $ESC5 | Where-Object Issue -Like '* Owner rights *' | ForEach-Object { # TODO This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" object to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC6) {
        $ESC6 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the Certificate Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            $WarningError = 'n'
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    if ($ESC11) {
        $ESC11 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable the IF_ENFORCEENCRYPTICERTREQUEST flag on the Certificate Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            $WarningError = 'n'
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable the IF_ENFORCEENCRYPTICERTREQUEST flag. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    if ($ESC13) {
        $ESC13 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'CCOMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host 'Continue with this operation? [Y] Yes ' -NoNewline
            Write-Host '[N] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No: ' -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "Mode 4 Complete! There are no more issues that Locksmith can automatically resolve.`n" -ForegroundColor Green
    Write-Host 'If you experience any operational impact from using Locksmith Mode 4, use ' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1 ' -ForegroundColor White
    Write-Host "to revert all changes made by Locksmith. It can be found in the current working directory.`n"
    Write-Host @"
[!] Locksmith cannot automatically resolve all AD CS issues at this time.
There may be more AD CS issues remaining in your environment.
Use Locksmith in Modes 0-3 to further investigate your environment
or reach out to the Locksmith team for assistance. We'd love to help!`n
"@ -ForegroundColor Yellow
}

function Invoke-Scans {
    <#
    .SYNOPSIS
        Invoke-Scans.ps1 is a script that performs various scans on ADCS (Active Directory Certificate Services) objects.

    .PARAMETER Scans
        Specifies the type of scans to perform. Multiple scan options can be provided as an array. The default value is 'All'.
        The available scan options are: 'Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'ESC9', 'ESC11',
            'ESC13', 'ESC15, 'EKUwu', 'ESC16', 'ESC17', 'All', 'PromptMe'.

    .NOTES
        - The script requires the following functions to be defined: Find-AuditingIssue, Find-ESC1, Find-ESC2, Find-ESC3C1,
          Find-ESC3C2, Find-ESC4, Find-ESC5, Find-ESC6, Find-ESC8, Find-ESC9, Find-ESC11, Find-ESC13, Find-ESC15, Find-ESC16
        - The script uses Out-GridView or Out-ConsoleGridView for interactive selection when the 'PromptMe' scan option is chosen.
        - The script returns a hash table containing the results of the scans.

    .EXAMPLE
    Invoke-Scans
    # Perform all scans

    .EXAMPLE
    Invoke-Scans -Scans 'Auditing', 'ESC1'
    # Perform only the 'Auditing' and 'ESC1' scans

    .EXAMPLE
    Invoke-Scans -Scans 'PromptMe'
    # Prompt the user to select the scans to perform
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Performing multiple scans.')]
    param (
        # Could split Scans and PromptMe into separate parameter sets.
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$ClientAuthEkus,
        [Parameter(Mandatory)]
        [string]$ServerAuthEkus,
        [Parameter(Mandatory)]
        [string]$DangerousRights,
        [Parameter(Mandatory)]
        [string]$EnrollmentAgentEKU,
        [Parameter(Mandatory)]
        [int]$Mode,
        [Parameter(Mandatory)]
        [string]$SafeObjectTypes,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$SafeOwners,
        [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'EKUwu', 'ESC16', 'ESC17', 'All', 'PromptMe')]
        [array]$Scans = 'All',
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$PreferredOwner
    )

    if ( $Scans -eq 'PromptMe' ) {
        $GridViewTitle = 'Select the tests to run and press Enter or click OK to continue...'

        # Check for Out-GridView or Out-ConsoleGridView
        if ((Get-Command Out-ConsoleGridView -ErrorAction SilentlyContinue) -and ($PSVersionTable.PSVersion.Major -ge 7)) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-ConsoleGridView -OutputMode Multiple -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        else {
            # To Do: Check for admin and prompt to install features/modules or revert to 'All'.
            Write-Information "Out-GridView and Out-ConsoleGridView were not found on your system. Defaulting to 'All'."
            $Scans = 'All'
        }
    }

    switch ( $Scans ) {
        Auditing {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
        }
        ESC1 {
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        ESC2 {
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        ESC3 {
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3C1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            [array]$ESC3 += Find-ESC3C2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        ESC4 {
            Write-Host 'Identifying AD CS templates with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        ESC5 {
            Write-Host 'Identifying AD CS objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -UnsafeUsers $UnsafeUsers
        }
        ESC6 {
            Write-Host 'Identifying Issuing CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC7 {
            Write-Host 'Identifying Issuing CAs with Non-Standard Admins (ESC7)...'
            [array]$ESC7 = Find-ESC7 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers -SafeUsers $SafeUsers
        }
        ESC8 {
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC9 {
            Write-Host 'Identifying AD CS templates with szOID_NTDS_CA_SECURITY_EXT disabled (ESC9)...'
            [array]$ESC9 = Find-ESC9 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        ESC11 {
            Write-Host 'Identifying Issuing CAs with IF_ENFORCEENCRYPTICERTREQUEST disabled (ESC11)...'
            [array]$ESC11 = Find-ESC11 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC13 {
            Write-Host 'Identifying AD CS templates with dangerous ESC13 configurations...'
            [array]$ESC13 = Find-ESC13 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEKUs -UnsafeUsers $UnsafeUsers
        }
        ESC15 {
            Write-Host 'Identifying AD CS templates with dangerous ESC15/EKUwu configurations...'
            [array]$ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        EKUwu {
            Write-Host 'Identifying AD CS templates with dangerous ESC15/EKUwu configurations...'
            [array]$ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC16 {
            Write-Host 'Identifying Issuing CAs with szOID_NTDS_CA_SECURITY_EXT disabled (ESC16)...'
            [array]$ESC16 = Find-ESC16 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
        }
        ESC17 {
            Write-Host 'Identifying AD CS templates with dangerous ESC17 configurations...'
            [array]$ESC17 = Find-ESC17 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ServerAuthEKUs $ServerAuthEKUs -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
        All {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3C1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            [array]$ESC3 += Find-ESC3C2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -Mode $Mode -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with Non-Standard Admins (ESC7)...'
            [array]$ESC7 = Find-ESC7 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers -SafeUsers $SafeUsers
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with szOID_NTDS_CA_SECURITY_EXT disabled (ESC9)...'
            [array]$ESC9 = Find-ESC9 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with IF_ENFORCEENCRYPTICERTREQUEST disabled (ESC11)...'
            [array]$ESC11 = Find-ESC11 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC13 configurations...'
            [array]$ESC13 = Find-ESC13 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC15 configurations...'
            [array]$ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying Certificate Authorities with szOID_NTDS_CA_SECURITY_EXT disabled (ESC16)...'
            [array]$ESC16 = Find-ESC16 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC17 configurations...'
            [array]$ESC17 = Find-ESC17 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ServerAuthEKUs $ServerAuthEkus -Mode $Mode -UnsafeUsers $UnsafeUsers
        }
    }

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC7 + $ESC8 + $ESC9 + $ESC11 + $ESC13 + $ESC15 + $ESC16 + $ESC17

    # If these are all empty = no issues found, exit
    if ($AllIssues.Count -lt 1) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found. :)" -ForegroundColor Green
        break
    }

    # Return a hash table of array names (keys) and arrays (values) so they can be directly referenced with other functions
    return @{
        AllIssues      = $AllIssues
        AuditingIssues = $AuditingIssues
        ESC1           = $ESC1
        ESC2           = $ESC2
        ESC3           = $ESC3
        ESC4           = $ESC4
        ESC5           = $ESC5
        ESC6           = $ESC6
        ESC7           = $ESC7
        ESC8           = $ESC8
        ESC9           = $ESC9
        ESC11          = $ESC11
        ESC13          = $ESC13
        ESC15          = $ESC15
        ESC16          = $ESC16
        ESC17          = $ESC17
    }
}

<#
.SYNOPSIS
Create a dictionary of the escalation paths and insecure configurations that Locksmith scans for.

.DESCRIPTION
The New-Dictionary function is used to instantiate an array of objects that contain the names, definitions,
descriptions, code used to find, code used to fix, and reference URLs. This is invoked by the module's main function.

.NOTES

    VulnerableConfigurationItem Class Definition:
        Version         Update each time the class definition or the dictionary below is changed.
        Name            The short name of the vulnerable configuration item (VCI).
        Category        The high level category of VCI types, including escalation path, server configuration, GPO setting, etc.
        Subcategory     The subcategory of vulnerable configuration item types.
        Summary         A summary of the vulnerability and how it can be abused.
        FindIt          The name of the function that is used to look for the VCI, stored as an invocable scriptblock.
        FixIt           The name of the function that is used to fix the VCI, stored as an invocable scriptblock.
        ReferenceUrls   An array of URLs that are used as references to learn more about the VCI.
#>

function New-Dictionary {
    class VulnerableConfigurationItem {
        static [string] $Version = '2024.11.03.000'
        [string]$Name
        [ValidateSet('Escalation Path', 'Server Configuration', 'GPO Setting')][string]$Category
        [string]$Subcategory
        [string]$Summary
        [scriptblock]$FindIt
        [scriptblock]$FixIt
        [uri[]]$ReferenceUrls
    }

    [VulnerableConfigurationItem[]]$Dictionary = @(
        [VulnerableConfigurationItem]@{
            Name          = 'ESC1'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Client Authentication Templates'
            Summary       = ''
            FindIt        = { Find-ESC1 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC1'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC2'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable SubCA/Any Purpose Templates'
            Summary       = ''
            FindIt        = { Find-ESC2 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC2'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC3'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Enrollment Agent Templates'
            Summary       = ''
            FindIt        = {
                Find-ESC3C1
                Find-ESC3C2
            }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Enrollment%20Agent%20Templates%20%E2%80%94%20ESC3'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC4'
            Category      = 'Escalation Path'
            Subcategory   = 'Certificate Templates with Vulnerable Access Controls'
            Summary       = ''
            FindIt        = { Find-ESC4 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Template%20Access%20Control%20%E2%80%94%20ESC4'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC5'
            Category      = 'Escalation Path'
            Subcategory   = 'PKI Objects with Vulnerable Access Control'
            Summary       = ''
            FindIt        = { Find-ESC5 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20PKI%20Object%20Access%20Control%20%E2%80%94%20ESC5'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC6'
            Category      = 'Escalation Path'
            Subcategory   = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
            Summary       = ''
            FindIt        = { Find-ESC6 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=EDITF_ATTRIBUTESUBJECTALTNAME2%20%E2%80%94%20ESC6'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC7'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Certificate Authority Access Control'
            Summary       = ''
            FindIt        = { Find-ESC7 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Authority%20Access%20Control%20%E2%80%94%20ESC7'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC8'
            Category      = 'Escalation Path'
            Subcategory   = 'AD CS HTTP Endpoints Vulnerable to NTLM Relay'
            Summary       = ''
            FindIt        = { Find-ESC8 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=NTLM%20Relay%20to%20AD%20CS%20HTTP%20Endpoints'
        },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC9'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC9}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC10'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC10}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC11'
            Category      = 'Escalation Path'
            Subcategory   = 'IF_ENFORCEENCRYPTICERTREQUEST'
            Summary       = ''
            FindIt        = { Find-ESC11 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC13'
            Category      = 'Escalation Path'
            Subcategory   = 'Certificate Template linked to Group'
            Summary       = ''
            FindIt        = { Find-ESC13 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53'
        }, [VulnerableConfigurationItem]@{
            Name          = 'ESC15/EKUwu'
            Category      = 'Escalation Path'
            Subcategory   = 'Certificate Template using Schema V1'
            Summary       = ''
            FindIt        = { Find-ESC15 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'Auditing'
            Category      = 'Server Configuration'
            Subcategory   = 'Gaps in auditing on certificate authorities and AD CS objects.'
            Summary       = ''
            FindIt        = { Find-AuditingIssue }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = @('https://github.com/jakehildreth/Locksmith', 'https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/designing-and-implementing-a-pki-part-i-design-and-planning/ba-p/396953')
        }
    )
    return $Dictionary
}

function New-OutputPath {
    <#
    .SYNOPSIS
        Creates output directories for each forest.

    .DESCRIPTION
        This script creates one output directory per forest specified in the $Targets variable.
        The output directories are created under the $OutputPath directory.

    .PARAMETER Targets
        Specifies the forests for which output directories need to be created.

    .PARAMETER OutputPath
        Specifies the base path where the output directories will be created.

    .EXAMPLE
        New-OutputPath -Targets "Forest1", "Forest2" -OutputPath "C:\Output"
        This example creates two output directories named "Forest1" and "Forest2" under the "C:\Output" directory.

    #>

    [CmdletBinding(SupportsShouldProcess)]
    param ()
    # Create one output directory per forest
    foreach ( $forest in $Targets ) {
        $ForestPath = $OutputPath + "`\" + $forest
        New-Item -Path $ForestPath -ItemType Directory -Force  | Out-Null
    }
}

function Set-AdditionalCAProperty {
    <#
    .SYNOPSIS
        Sets additional properties for a Certificate Authority (CA) object.

    .DESCRIPTION
        This script sets additional properties for a Certificate Authority (CA) object.
        It takes an array of AD CS Objects as input, which represent the CA objects to be processed.
        The script filters the AD CS Objects based on the objectClass property and performs the necessary operations
        to set the additional properties.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS Objects to be processed. This parameter is mandatory and supports pipeline input.

    .PARAMETER Credential
        Specifies the PSCredential object to be used for authentication when accessing the CA objects.
        If not provided, the script will use the current user's credentials.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Filter
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -ForestGC 'dc1.ad.dotdot.horse:3268'

    .NOTES
        Author: Jake Hildreth
        Date: July 15, 2022
    #>

    # TODO REfactor to move the creation of each property into its own function

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(
            Mandatory,
            ValueFromPipeline = $true)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [PSCredential]$Credential,
        $ForestGC
    )

    begin {
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy') ) {
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                $code = @'
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
                            return true;
                        }
                    }
'@
                Add-Type -TypeDefinition $code -Language CSharp
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }
            else {
                Add-Type @'
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    using System.Net.Security;
                    public class TrustAllCertsPolicy {
                        public static bool TrustAllCerts(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
                            return true;
                        }
                    }
'@
                # Set the ServerCertificateValidationCallback
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [TrustAllCertsPolicy]::TrustAllCerts
            }
        }
    }

    process {
        $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
            $CAEnrollmentEndpoint = @()
            foreach ($directory in @('certsrv/', "$($_.Name)_CES_Kerberos/service.svc", "$($_.Name)_CES_Kerberos/service.svc/CES", 'ADPolicyProvider_CEP_Kerberos/service.svc', 'certsrv/mscep/')) {
                $URL = "://$($_.dNSHostName)/$directory"
                try {
                    $Auth = 'NTLM'
                    $FullURL = "http$URL"
                    $Request = [System.Net.WebRequest]::Create($FullURL)
                    $Cache = [System.Net.CredentialCache]::New()
                    $Cache.Add([System.Uri]::new($FullURL), $Auth, [System.Net.CredentialCache]::DefaultNetworkCredentials)
                    $Request.Credentials = $Cache
                    $Request.Timeout = 100
                    $Request.GetResponse() | Out-Null
                    $CAEnrollmentEndpoint += @{
                        'URL'  = $FullURL
                        'Auth' = $Auth
                    }
                }
                catch {
                    try {
                        $Auth = 'NTLM'
                        $FullURL = "https$URL"
                        $Request = [System.Net.WebRequest]::Create($FullURL)
                        $Cache = [System.Net.CredentialCache]::New()
                        $Cache.Add([System.Uri]::new($FullURL), $Auth, [System.Net.CredentialCache]::DefaultNetworkCredentials)
                        $Request.Credentials = $Cache
                        $Request.Timeout = 100
                        $Request.GetResponse() | Out-Null
                        $CAEnrollmentEndpoint += @{
                            'URL'  = $FullURL
                            'Auth' = $Auth
                        }
                    }
                    catch {
                        try {
                            $Auth = 'Negotiate'
                            $FullURL = "https$URL"
                            $Request = [System.Net.WebRequest]::Create($FullURL)
                            $Cache = [System.Net.CredentialCache]::New()
                            $Cache.Add([System.Uri]::new($FullURL), $Auth, [System.Net.CredentialCache]::DefaultNetworkCredentials)
                            $Request.Credentials = $Cache
                            $Request.Timeout = 100
                            $Request.GetResponse() | Out-Null
                            $CAEnrollmentEndpoint += @{
                                'URL'  = $FullURL
                                'Auth' = $Auth
                            }
                        }
                        catch {
                            Write-Debug "There may have been an error or something nothing found. $_"
                        }
                    }
                }
            }
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $CAHostname = $_.dNSHostName.split('.')[0]
            if ($Credential) {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC -Credential $Credential).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC -Credential $Credential).DnsHostname
            }
            else {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC ).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC).DnsHostname
            }
            $ping = if ($CAHostFQDN) {
                Test-Connection -ComputerName $CAHostFQDN -Count 1 -Quiet 
            }
            else {
                Write-Warning "Unable to resolve $($_.Name) Fully Qualified Domain Name (FQDN)" 
            }
            if ($ping) {
                try {
                    if ($Credential) {
                        $CertutilAudit = Invoke-Command -ComputerName $CAHostFQDN -Credential $Credential -ScriptBlock { certutil -config $using:CAFullName -getreg CA\AuditFilter }
                    }
                    else {
                        $CertutilAudit = certutil -config $CAFullName -getreg CA\AuditFilter
                    }
                }
                catch {
                    $AuditFilter = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilFlag = Invoke-Command -ComputerName $CAHostFQDN -Credential $Credential -ScriptBlock { certutil -config $using:CAFullName -getreg policy\EditFlags }
                    }
                    else {
                        $CertutilFlag = certutil -config $CAFullName -getreg policy\EditFlags
                    }
                }
                catch {
                    $SANFlag = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilInterfaceFlag = Invoke-Command -ComputerName $CAHostFQDN -Credential $Credential -ScriptBlock { certutil -config $using:CAFullName -getreg CA\InterfaceFlags }
                    }
                    else {
                        $CertutilInterfaceFlag = certutil -config $CAFullName -getreg CA\InterfaceFlags
                    }
                }
                catch {
                    $InterfaceFlag = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilSecurity = Invoke-Command -ComputerName $CAHostFQDN -Credential $Credential -ScriptBlock { certutil -config $using:CAFullName -getreg CA\Security }
                    }
                    else {
                        $CertutilSecurity = certutil -config $CAFullName -getreg CA\Security
                    }
                }
                catch {
                    $CAAdministrator = 'Failure'
                    $CertificateManager = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilDisableExtensionList = Invoke-Command -ComputerName $CAHostFQDN -Credential $Credential -ScriptBlock { certutil -config $using:CAFullName -getreg policy\DisableExtensionList }
                    }
                    else {
                        $CertutilDisableExtensionList = certutil -config $CAFullName -getreg policy\DisableExtensionList
                    }
                }
                catch {
                    $CertutilDisableExtensionList = 'Failure'
                }
            }
            else {
                $AuditFilter = 'CA Unavailable'
                $SANFlag = 'CA Unavailable'
                $InterfaceFlag = 'CA Unavailable'
                $CAAdministrator = 'CA Unavailable'
                $CertificateManager = 'CA Unavailable'
                $DisableExtensionList = 'CA Unavailable'
            }
            if ($CertutilAudit) {
                try {
                    [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
                    $AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
                }
                catch {
                    try {
                        [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
                        $AuditFilter = $AuditFilter.split('=')[1].trim()
                    }
                    catch {
                        $AuditFilter = 'Never Configured'
                    }
                }
            }
            if ($CertutilFlag) {
                [string]$SANFlag = $CertutilFlag | Select-String ' EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 \('
                if ($SANFlag) {
                    $SANFlag = 'Yes'
                }
                else {
                    $SANFlag = 'No'
                }
            }
            if ($CertutilInterfaceFlag) {
                [string]$InterfaceFlag = $CertutilInterfaceFlag | Select-String ' IF_ENFORCEENCRYPTICERTREQUEST -- 200 \('
                if ($InterfaceFlag) {
                    $InterfaceFlag = 'Yes'
                }
                else {
                    $InterfaceFlag = 'No'
                }
            }
            if ($CertutilSecurity) {
                [string[]]$CAAdministrator = $CertutilSecurity | ForEach-Object {
                    if ($_ -match '^.*Allow.*CA Administrator.*.*\t(.*)$') {
                        $matches[1].ToString()
                    }
                }
                [string[]]$CertificateManager = $CertutilSecurity | ForEach-Object {
                    if ($_ -match '^.*Allow.*Certificate Manager.*\t(.*)$') {
                        $matches[1].ToString()
                    }
                }
            }
            if ($CertutilDisableExtensionList) {
                [string]$DisableExtensionList = $CertutilDisableExtensionList | Select-String '1\.3\.6\.1\.4\.1\.311\.25\.2'
                if ($DisableExtensionList) {
                    $DisableExtensionList = 'Yes'
                }
                else {
                    $DisableExtensionList = 'No'
                }
            }
            Add-Member -InputObject $_ -MemberType NoteProperty -Name AuditFilter -Value $AuditFilter -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAEnrollmentEndpoint -Value $CAEnrollmentEndpoint -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAFullName -Value $CAFullName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostname -Value $CAHostname -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostDistinguishedName -Value $CAHostDistinguishedName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name SANFlag -Value $SANFlag -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name InterfaceFlag -Value $InterfaceFlag -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAAdministrator -Value $CAAdministrator -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CertificateManager -Value $CertificateManager -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name DisableExtensionList -Value $DisableExtensionList -Force
        }
    }
}

function Set-AdditionalTemplateProperty {
    <#
    .SYNOPSIS
        Sets additional properties on a template object.

    .DESCRIPTION
        This script sets additional properties on a template object.
        It takes an array of AD CS Objects as input, which includes the templates to be processed and CA objects that
        detail which templates are Enabled.
        The script filters the AD CS Objects based on the objectClass property and performs the necessary operations
        to set the additional properties.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS Objects to be processed. This parameter is mandatory and supports pipeline input.

    .PARAMETER Credential
        Specifies the PSCredential object to be used for authentication when accessing the CA objects.
        If not provided, the script will use the current user's credentials.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Targets (Get-Target)
        Set-AdditionalTemplateProperty -ADCSObjects $ADCSObjects -ForestGC 'dc1.ad.dotdot.horse:3268'
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects
    )

    process {
        $ADCSObjects | Where-Object objectClass -Match 'pKICertificateTemplate' -PipelineVariable template | ForEach-Object {
            # Write-Host "[?] Checking if template `"$($template.Name)`" is Enabled on any Certification Authority." -ForegroundColor Blue
            $Enabled = $false
            $EnabledOn = @()
            foreach ($ca in ($ADCSObjects | Where-Object objectClass -EQ 'pKIEnrollmentService')) {
                if ($ca.certificateTemplates -contains $template.Name) {
                    $Enabled = $true
                    $EnabledOn += $ca.Name
                }

                $template | Add-Member -NotePropertyName Enabled -NotePropertyValue $Enabled -Force
                $template | Add-Member -NotePropertyName EnabledOn -NotePropertyValue $EnabledOn -Force
            }
        }
    }
}

function Set-RiskRating {
    <#
        .SYNOPSIS
        This function takes an Issue object as input and assigns a numerical risk score depending on issue conditions.

        .DESCRIPTION
        Risk of Issue is based on:
        - Issue type: Templates issues are more risky than CA/Object issues by default.
        - Template status: Enabled templates are more risky than disabled templates.
        - Principals: Single users are less risky than groups, and custom groups are less risky than default groups.
        - Principal type: AD Admins aren't risky. gMSAs have little risk (assuming proper controls). Non-admins are most risky
        - Modifiers: Some issues are present a higher risk when certain conditions are met.

        .PARAMETER Issue
        A PSCustomObject that includes all pertinent information about an AD CS issue.

        .INPUTS
        PSCustomObject

        .OUTPUTS
        None. This function sets a new attribute on each Issue object and returns nothing to the pipeline.

        .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-519$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $ESC4Issues = Find-ESC4 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes -Mode 1
        foreach ($issue in $ESC4Issues) {
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
        }

        .LINK
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Issue,
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers
    )

    #requires -Version 5

    $RiskValue = 0
    $RiskName = ''
    $RiskScoring = @()

    # CA issues don't rely on a principal and have a base risk of Medium.
    if ($Issue.Technique -in @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC17')) {
        $RiskValue += 3
        $RiskScoring += 'Base Score: 3'

        if ($Issue.CAEnrollmentEndpoint -like 'http:*') {
            $RiskValue += 2
            $RiskScoring += 'HTTP Enrollment: +2'
        }

        if ($Issue.Technique -eq 'ESC7') {
            # If an Issue can be tied to a principal, the principal's objectClass impacts the Issue's risk
            $SID = $Issue.IdentityReferenceSID.ToString()
            $IdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $SID } | Select-Object objectClass

            if ($Issue.IdentityReferenceSID -match $UnsafeUsers) {
                # Authenticated Users, Domain Users, Domain Computers etc. are very risky
                $RiskValue += 2
                $RiskScoring += 'Very Large Group: +2'
            }
            elseif ($IdentityReferenceObjectClass -eq 'group') {
                # Groups are riskier than individual principals
                $RiskValue += 1
                $RiskScoring += 'Group: +1'
            }
            elseif ($Issue.IdentityReferenceSID -notmatch $UnsafeUsers -and
                $Issue.IdentityReferenceSID -notmatch $SafeUsers -and
                $IdentityReferenceObjectClass -notlike '*ManagedServiceAccount') {
                $RiskValue += 1
                $RiskScoring += 'Unprivileged Principal: +1'
            }
        }

        # Modifiers that rely on the existence of other ESCs
        if ($Issue.Technique -eq 'ESC6') {
            [array]$ESC9 = Find-ESC9 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus -UnsafeUsers $UnsafeUsers
            [array]$ESC16 = Find-ESC16 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers
            $ESC9and16 = $ESC9 + $ESC16
            if ($ESC9and16) {
                $RiskValue += 2
                $RiskScoring += "Additional risky configurations exist which make this issue more severe: +2"
                foreach ($otherIssue in $ESC9and16) {
                    $RiskScoring += "  - $($otherIssue.Technique) exists on $($otherIssue.Name)"
                }
            } # end if ($ESC9and16)
        }

        # TODO Check NtAuthCertificates for CA thumbprint. If found, +2, else -1
        # TODO Check if NTLMv1 is allowed.
    }

    # Template and object issues rely on a principal and have complex scoring.
    if ($Issue.Technique -notin @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC17')) {
        $RiskScoring += 'Base Score: 0'

        # Templates are more dangerous when enabled, but objects cannot be enabled/disabled.
        if ($Issue.Technique -ne 'ESC5') {
            if ($Issue.Enabled) {
                $RiskValue += 1
                $RiskScoring += 'Enabled: +1'
            }
            else {
                $RiskValue -= 2
                $RiskScoring += 'Disabled: -2'
            }
        }

        # ESC1 and ESC4 templates are more dangerous than other templates because they can result in immediate compromise.
        if ($Issue.Technique -in @('ESC1', 'ESC4')) {
            $RiskValue += 1
            $RiskScoring += "$($Issue.Technique) +1"
        }

        # If an Issue can be tied to a principal, the principal's objectClass impacts the Issue's risk
        $SID = $Issue.IdentityReferenceSID.ToString()
        $IdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $SID } | Select-Object objectClass


        if ($Issue.IdentityReferenceSID -match $UnsafeUsers) {
            # Authenticated Users, Domain Users, Domain Computers etc. are very risky
            $RiskValue += 2
            $RiskScoring += 'Very Large Group: +2'
        }
        elseif ($IdentityReferenceObjectClass -eq 'group') {
            # Groups are riskier than individual principals
            $RiskValue += 1
            $RiskScoring += 'Group: +1'
        }
        elseif ($Issue.IdentityReferenceSID -notmatch $UnsafeUsers -and
            $Issue.IdentityReferenceSID -notmatch $SafeUsers -and
            $IdentityReferenceObjectClass -notlike '*ManagedServiceAccount') {
            $RiskValue += 1
            $RiskScoring += 'Unprivileged Principal: +1'
        }

        # Safe users and managed service accounts are inherently safer than other principals - except in ESC3 Condition 2 and ESC9!
        if (($Issue.Technique -eq 'ESC9') -or ($Issue.Technique -eq 'ESC3' -and $Issue.Condition -eq 2)) {
            if ($Issue.IdentityReferenceSID -match $SafeUsers) {
                # Safe Users are admins. Authenticating as an admin is bad.
                $RiskValue += 2
                $RiskScoring += 'Privileged Principal: +2'
            }
            elseif ($IdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                # Managed Service Accounts are *probably* privileged in some way.
                $RiskValue += 1
                $RiskScoring += 'Managed Service Account: +1'
            }
        }
        elseif ($Issue.IdentityReferenceSID -notmatch $SafeUsers -and $IdentityReferenceObjectClass -notlike '*ManagedServiceAccount') {
            $RiskValue += 1
            $RiskScoring += 'Unprivileged Principal: +1'
        }

        # Modifiers that rely on the existence of other ESCs
        # ESC2 and ESC3C1 are more dangerous if ES3C2 templates exist or certain ESC15 templates are enabled
        if ($Issue.Technique -eq 'ESC2' -or ($Issue.Technique -eq 'ESC3' -and $Issue.Condition -eq 1)) {
            $ESC3C2 = Find-ESC3C2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
                Where-Object { $_.Enabled -eq $true }
            $ESC3C2Names = @(($ESC3C2 | Select-Object -Property Name -Unique).Name)
            if ($ESC3C2Names) {
                $CheckedESC3C2Templates = @{}
                foreach ($name in $ESC3C2Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC3C2 | Where-Object Name -EQ $name) ) {
                        if ($CheckedESC3C2Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC3C2Templates.$($esc.Name)
                        }
                        else {
                            $CheckedESC3C2Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $SafeUsers) {
                            # Safe Users are admins. Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        }
                        elseif ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups that contain practically all principals and likely including admins.
                            # Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        }
                        elseif ($escIdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                            # Managed Service Accounts are *probably* privileged in some way.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        }
                        elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principals.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC3C2Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC3C2Templates.$($esc.Name) -join ', ')) are able to enroll in an enabled ESC3 Condition 2 template ($name): +$OtherTemplateRisk"
                } # end foreach ($name)
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC3C2Names)

            # Default 'User' and 'Machine' templates are more dangerous
            $ESC15 = Find-ESC15 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
                Where-Object { $_.Enabled -eq $true }
            $ESC15Names = @(($ESC15 | Where-Object Name -In @('Machine', 'User')).Name)
            if ($ESC15Names) {
                $CheckedESC15Templates = @{}
                foreach ($name in $ESC15Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC15 | Where-Object Name -EQ $name) ) {
                        if ($CheckedESC15Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC15Templates.$($esc.Name)
                        }
                        else {
                            $Principals = @()
                            $CheckedESC15Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $SafeUsers) {
                            # Safe Users are admins. Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        }
                        elseif ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups that contain practically all principals and likely including admins.
                            # Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        }
                        elseif ($escIdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                            # Managed Service Accounts are *probably* privileged in some way.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        }
                        elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principals.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC15Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC15Templates.$($esc.Name) -join ', ')) are able to enroll in an enabled ESC15/EKUwu template ($name)): +$OtherTemplateRisk"
                } # end foreach ($name)
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC15Names)
            $RiskValue += $OtherTemplateRisk
        }

        # ESC3 Condition 2 and ESC15 User/Machine templates are only dangerous if ESC2 or ESC3 Condition 1 templates exist.
        if ( ($Issue.Technique -match 'ESC15' -and $Issue.Name -match 'User|Machine') -or
            ($Issue.Technique -eq 'ESC3' -and $Issue.Condition -eq 2)
        ) {
            $ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
                Where-Object { $_.Enabled -eq $true }
            $ESC2Names = @(($ESC2 | Select-Object -Property Name -Unique).Name)
            if ($ESC2Names) {
                $CheckedESC2Templates = @{}
                foreach ($name in $ESC2Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC2 | Where-Object Name -EQ $name) ) {
                        if ($CheckedESC2Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC2Templates.$($esc.Name)
                        }
                        else {
                            $CheckedESC2Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        }
                        elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principals.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC2Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC2Templates.$($esc.Name) -join ', ')) are able to enroll in an enabled ESC2 template ($name): +$OtherTemplateRisk"
                } # end foreach ($name)
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC2Names)

            $ESC3C1 = Find-ESC3C1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers  -SkipRisk |
                Where-Object { $_.Enabled -eq $true }
            $ESC3C1Names = @(($ESC3C1 | Select-Object -Property Name -Unique).Name)
            if ($ESC3C1Names) {
                $CheckedESC3C1Templates = @{}
                foreach ($name in $ESC3C1Names) {
                    $OtherTemplateRisk = 0
                    $Principals = @()
                    foreach ($esc in $($ESC3C1 | Where-Object Name -EQ $name) ) {
                        if ($CheckedESC3C1Templates.GetEnumerator().Name -contains $esc.Name) {
                            $Principals = $CheckedESC3C1Templates.$($esc.Name)
                        }
                        else {
                            $CheckedESC3C1Templates = @{
                                $($esc.Name) = @()
                            }
                        }
                        $escSID = $esc.IdentityReferenceSID.ToString()
                        $escIdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $escSID } | Select-Object objectClass
                        if ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        }
                        elseif ($escIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principals.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        }
                        $CheckedESC3C1Templates.$($esc.Name) = $Principals
                    }
                    $RiskScoring += "Principals ($($CheckedESC3C1Templates.$($esc.Name) -join ', ')) are able to enroll in an enabled ESC3C1 template ($name): +$OtherTemplateRisk"
                } # end foreach ($name...
                if ($OtherTemplateRisk -ge 2) {
                    $OtherTemplateRisk = 2
                }
            } # end if ($ESC3C1Names)
            $RiskValue += $OtherTemplateRisk
        }

        # Disabled ESC1, ESC2, ESC3, ESC4, ESC9, and ESC15 templates are more dangerous if there's an ESC5 on one or more CA objects
        if ($Issue.Technique -match 'ESC1|ESC2|ESC3|ESC4|ESC9' -and $Issue.Enabled -eq $false ) {
            $ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers -DangerousRights $DangerousRights -SafeOwners '-519$' -SafeObjectTypes $SafeObjectTypes -SkipRisk |
                Where-Object { $_.objectClass -eq 'pKIEnrollmentService' }
            $ESC5Names = @(($ESC5 | Select-Object -Property Name -Unique).Name)
            if ($ESC5Names) {
                $CheckedESC5Templates = @{}
                foreach ($name in $ESC5Names) {
                    $OtherIssueRisk = 0
                    $Principals = @()
                    foreach ($OtherIssue in $($ESC5 | Where-Object Name -EQ $name) ) {
                        if ($CheckedESC5Templates.GetEnumerator().Name -contains $OtherIssue.Name) {
                            $Principals = $CheckedESC5Templates.$($OtherIssue.Name)
                        }
                        else {
                            $CheckedESC5Templates = @{
                                $($OtherIssue.Name) = @()
                            }
                        }
                        $OtherIssueSID = $OtherIssue.IdentityReferenceSID.ToString()
                        $OtherIssueIdentityReferenceObjectClass = (Get-ADObject -Filter { objectSid -eq $OtherIssueSID } | Select-Object objectClass).objectClass
                        if ($OtherIssueSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups.
                            $Principals += $OtherIssue.IdentityReference.Value
                            $OtherIssueRisk += 2
                        }
                        elseif ($OtherIssueIdentityReferenceObjectClass -eq 'group') {
                            # Groups are more dangerous than individual principals.
                            $Principals += $OtherIssue.IdentityReference.Value
                            $OtherIssueRisk += 1
                        }
                        else {
                            $Principals += $OtherIssue.IdentityReference.Value
                            $OtherIssueRisk += 0.1
                        }
                        $CheckedESC5Templates.$($OtherIssue.Name) = $Principals
                    } # forech ($OtherIssue)
                    if ($OtherIssueRisk -ge 2) {
                        $OtherIssueRisk = 2
                    }
                    $RiskScoring += "Principals ($($CheckedESC5Templates.$($OtherIssue.Name) -join ', ')) are able to modify CA Host object ($name): +$OtherIssueRisk"
                } # end foreach ($name...
            } # end if ($ESC5Names)
            $RiskValue += $OtherIssueRisk
        }

        # ESC5 objectClass determines risk
        if ($Issue.Technique -eq 'ESC5') {
            if ($Issue.objectClass -eq 'certificationAuthority' -and $Issue.distinguishedName -like 'CN=NtAuthCertificates*') {
                # Being able to modify NtAuthCertificates is very bad.
                $RiskValue += 2
                $RiskScoring += 'NtAuthCertificates: +2'
            }
            switch ($Issue.objectClass) {
                # Being able to modify Root CA Objects is very bad.
                'certificationAuthority' {
                    $RiskValue += 2; $RiskScoring += 'Root Certification Authority bject: +2' 
                }
                # Being able to modify Issuing CA Objects is also very bad.
                'pKIEnrollmentService' {
                    $RiskValue += 2; $RiskScoring += 'Issuing Certification Authority Object: +2' 
                }
                # Being able to modify CA Hosts? Yeah... very bad.
                'computer' {
                    $RiskValue += 2; $RiskScoring += 'Certification Authority Host Computer: +2' 
                }
                # Being able to modify OIDs could result in ESC13 vulns.
                'msPKI-Enterprise-Oid' {
                    $RiskValue += 1; $RiskScoring += 'OID: +1' 
                }
                # Being able to modify PKS containers is bad.
                'container' {
                    $RiskValue += 1; $RiskScoring += 'Container: +1' 
                }
            }
        }
    }

    # ESC9/ESC16 are much more dangerous when ESC6 exists
    if ($Issue.Technique -match 'ESC9|ESC16') {
        $ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects -UnsafeUsers $UnsafeUsers -SkipRisk
        if ($ESC6) {
            $RiskValue += 2
            $RiskScoring += "One or more CAs have an ESC6: +2"
            foreach ($ca in $ESC6.CAFullName) {
                $RiskScoring += "  - ESC6 exists on $ca"
            }
        } # end if ($ESC6)
    }

    # Convert Value to Name
    $RiskName = switch ($RiskValue) {
        { $_ -le 1 } {
            'Informational' 
        }
        2 {
            'Low' 
        }
        3 {
            'Medium' 
        }
        4 {
            'High' 
        }
        { $_ -ge 5 } {
            'Critical' 
        }
    }

    # Write Risk attributes
    $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue $RiskValue -Force
    $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue $RiskName -Force
    $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue $RiskScoring -Force
}

function Show-LocksmithLogo {
    Write-Host '%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'
    Write-Host '%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'
    Write-Host '%%%%%%%%%%%%%%%%%#+==============#%%%%%%%%%%%%%%%%%'
    Write-Host '%%%%%%%%%%%%%%#=====================#%%%%%%%%%%%%%%'
    Write-Host '%%%%%%%%%%%%#=========================#%%%%%%%%%%%%'
    Write-Host '%%%%%%%%%%%=============================%%%%%%%%%%%'
    Write-Host '%%%%%%%%%#==============+++==============#%%%%%%%%%'
    Write-Host '%%%%%%%%#===========#%%%%%%%%%#===========#%%%%%%%%'
    Write-Host '%%%%%%%%==========%%%%%%%%%%%%%%%==========%%%%%%%%'
    Write-Host '%%%%%%%*=========%%%%%%%%%%%%%%%%%=========*%%%%%%%'
    Write-Host '%%%%%%%+========*%%%%%%%%%%%%%%%%%#=========%%%%%%%'
    Write-Host '%%%%%%%+========#%%%%%%%%%%%%%%%%%#=========%%%%%%%'
    Write-Host '%%%%%%%+========#%%%%%%%%%%%%%%%%%#=========%%%%%%%'
    Write-Host '%%%%%%%+========#%%%%%%%%%%%%%%%%%#=========%%%%%%%'
    Write-Host '%%%%%%%+========#%%%%%%%%%%%%%%%%%#=========%%%%%%%'
    Write-Host '%%%%%%%+========#%%%%%%%%%%%%%%%%%#=========%%%%%%%'
    Write-Host '%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'
    Write-Host '#=================================================#'
    Write-Host '#=================================================#'
    Write-Host '#=================+%%%============================#'
    Write-Host '#==================%%%%*==========================#'
    Write-Host '#===================*%%%%+========================#'
    Write-Host '#=====================#%%%%=======================#'
    Write-Host '#======================+%%%%#=====================#'
    Write-Host '#========================*%%%%*===================#'
    Write-Host '#========================+%%%%%===================#'
    Write-Host '#======================#%%%%%+====================#'
    Write-Host '#===================+%%%%%%=======================#'
    Write-Host '#=================#%%%%%+=========================#'
    Write-Host '#==============+%%%%%#============================#'
    Write-Host '#============*%%%%%+====+%%%%%%%%%%===============#'
    Write-Host '#=============%%*========+********+===============#'
    Write-Host '#=================================================#'
    Write-Host '#=================================================#'
    Write-Host '#=================================================#'
}

function Test-IsADAdmin {
    <#
    .SYNOPSIS
        Tests if the current user has administrative rights in Active Directory.
    .DESCRIPTION
        This function returns True if the current user is a Domain Admin (or equivalent) or False if not.
    .EXAMPLE
        Test-IsADAdmin
    .EXAMPLE
        if (!(Test-IsADAdmin)) { Write-Host "You are not running with Domain Admin rights and will not be able to make certain changes." -ForeGroundColor Yellow }
    #>
    if (
        # Need to test to make sure this checks domain groups and not local groups, particularly for 'Administrators' (reference SID instead of name?).
        ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Domain Admins") -or
        ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators") -or
        ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins")
    ) {
        return $true
    }
    else {
        return $false
    }
}

function Test-IsElevated {
    <#
    .SYNOPSIS
        Tests if PowerShell is running with elevated privileges (run as Administrator).
    .DESCRIPTION
        This function returns True if the script is being run as an administrator or False if not.
    .EXAMPLE
        Test-IsElevated
    .EXAMPLE
        if (!(Test-IsElevated)) { Write-Host "You are not running with elevated privileges and will not be able to make any changes." -ForeGroundColor Yellow }
    .EXAMPLE
        # Prompt to launch elevated if not already running as administrator:
        if (!(Test-IsElevated)) {
            $arguments = "& '" + $MyInvocation.MyCommand.definition + "'"
            Start-Process powershell -Verb runAs -ArgumentList $arguments
            Break
        }
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-IsLocalAccountSession {
    <#
    .SYNOPSIS
        Tests if the current session is running under a local user account or a domain account.
    .DESCRIPTION
        This function returns True if the current session is a local user or False if it is a domain user.
    .EXAMPLE
        Test-IsLocalAccountSession
    .EXAMPLE
        if ( (Test-IsLocalAccountSession) ) { Write-Host "You are running this script under a local account." -ForeGroundColor Yellow }
    #>
    [CmdletBinding()]

    $CurrentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $LocalSIDs = (Get-LocalUser).SID.Value
    if ($CurrentSID -in $LocalSIDs) {
        return $true
    }
}

function Test-IsMemberOfProtectedUsers {
    <#
        .SYNOPSIS
            Check to see if a user is a member of the Protected Users group.

        .DESCRIPTION
            This function checks to see if a specified user or the current user is a member of the Protected Users group in AD.
            It also checked the user's primary group ID in case that is set to 525 (Protected Users).

        .PARAMETER User
            The user that will be checked for membership in the Protected Users group. This parameter accepts input from the pipeline.

        .EXAMPLE
            This example will check if JaneDoe is a member of the Protected Users group.

            Test-IsMemberOfProtectedUsers -User JaneDoe

        .EXAMPLE
            This example will check if the current user is a member of the Protected Users group.

            Test-IsMemberOfProtectedUsers

        .INPUTS
            Active Directory user object, user SID, SamAccountName, etc

        .OUTPUTS
            Boolean
    #>


    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'The name of the group we are checking is plural.')]
    [OutputType([Boolean])]
    [CmdletBinding()]
    param (
        # User parameter accepts any input that is valid for Get-ADUser
        [Parameter(
            ValueFromPipeline = $true
        )]
        $User
    )

    begin {
        Import-Module ActiveDirectory
    }

    process {
        # Use the currently logged in user if none is specified
        # Get the user from Active Directory
        if (-not($User)) {
            # These two are different types. Fixed by referencing $CheckUser.SID later, but should fix here by using one type.
            $CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[-1]
            $CheckUser = Get-ADUser $CurrentUser -Properties primaryGroupID
        }
        else {
            $CheckUser = Get-ADUser $User -Properties primaryGroupID
        }

        # Get the Protected Users group by SID instead of by its name to ensure compatibility with any locale or language.
        $DomainSID = (Get-ADDomain).DomainSID.Value
        $ProtectedUsersSID = "$DomainSID-525"

        # Get members of the Protected Users group for the current domain. Recuse in case groups are nested in it.
        $ProtectedUsers = Get-ADGroupMember -Identity $ProtectedUsersSID -Recursive | Select-Object -Unique

        # Check if the current user is in the 'Protected Users' group
        if ($ProtectedUsers.SID.Value -contains $CheckUser.SID) {
            Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is a member of the Protected Users group."
            $true
        }
        else {
            # Check if the user's PGID (primary group ID) is set to the Protected Users group RID (525).
            if ( $CheckUser.primaryGroupID -eq '525' ) {
                $true
            }
            else {
                Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is not a member of the Protected Users group."
                $false
            }
        }
    }

    end {
    }
}

function Test-IsRecentVersion {
    <#
    .SYNOPSIS
        Check if the installed version of the Locksmith module is up to date.

    .DESCRIPTION
        This script checks the installed version of the Locksmith module against the latest release on GitHub.
        It determines if the installed version is considered "out of date" based on the number of days specified.
        If the installed version is out of date, a warning message is displayed along with information about the latest release.

    .PARAMETER Version
        Specifies the version number to check from the script.

    .PARAMETER Days
        Specifies the number of days past a module release date at which to consider the release "out of date".
        The default value is 60 days.

    .OUTPUTS
        System.Boolean
        Returns $true if the installed version is up to date, and $false if it is out of date.

    .EXAMPLE
        Test-IsRecentVersion -Version "2024.1" -Days 30
        True

        Test-IsRecentVersion -Version "2023.10" -Days 60
        WARNING: Your currently installed version of Locksmith (2.5) is more than 60 days old. We recommend that you update to ensure the latest findings are included.
        Locksmith Module Details:
        Latest Version:     2024.12.11
        Publishing Date:    01/28/2024 12:47:18
        Install Module:     Install-Module -Name Locksmith
        Standalone Script:  https://github.com/jakehildreth/locksmith/releases/download/v2.6/Invoke-Locksmith.zip
    #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        # Check a specific version number from the script
        [Parameter(Mandatory)]
        [string]$Version,
        # Define the number of days past a module release date at which to consider the release "out of date."
        [Parameter()]
        [int16]$Days = 60
    )

    # Strip the 'v' if it was used so the script can work with or without it in the input
    $Version = $Version.Replace('v', '')
    try {
        # Checking the most recent release in GitHub, but we could also use PowerShell Gallery.
        $Uri = "https://api.github.com/repos/jakehildreth/locksmith/releases"
        $Releases = Invoke-RestMethod -Uri $uri -Method Get -DisableKeepAlive -ErrorAction Stop
        $LatestRelease = $Releases | Sort-Object -Property Published_At -Descending | Select-Object -First 1
        # Get the release date of the currently running version via the version parameter
        [datetime]$InstalledVersionReleaseDate = ($Releases | Where-Object { $_.tag_name -like "?$Version" }).Published_at
        [datetime]$LatestReleaseDate = $LatestRelease.Published_at
        # $ModuleDownloadLink   = ( ($LatestRelease.Assets).Where({$_.Name -like "Locksmith-v*.zip"}) ).browser_download_url
        $ScriptDownloadLink = ( ($LatestRelease.Assets).Where({ $_.Name -eq 'Invoke-Locksmith.zip' }) ).browser_download_url

        $LatestReleaseInfo = @"
Locksmith Module Details:

Latest Version:`t`t $($LatestRelease.name)
Publishing Date: `t`t $LatestReleaseDate
Install Module:`t`t Install-Module -Name Locksmith
Standalone Script:`t $ScriptDownloadLink
"@
    }
    catch {
        Write-Warning "Unable to find the latest available version of the Locksmith module on GitHub." -WarningAction Continue
        # Find the approximate release date of the installed version. Handles version with or without 'v' prefix.
        $InstalledVersionMonth = [datetime]::Parse(($Version.Replace('v', '')).Replace('.', '-') + "-01")
        # Release date is typically the first Saturday of the month. Let's guess as close as possible!
        $InstalledVersionReleaseDate = $InstalledVersionMonth.AddDays( 6 - ($InstallVersionMonth.DayOfWeek) )
    }

    # The date at which to consider this module "out of date" is based on the $Days parameter
    $OutOfDateDate = (Get-Date).Date.AddDays(-$Days)
    $OutOfDateMessage = "Your currently installed version of Locksmith ($Version) is more than $Days days old. We recommend that you update to ensure the latest findings are included."

    # Compare the installed version release date to the latest release date
    if ( ($LatestReleaseDate) -and ($InstalledVersionReleaseDate -le ($LatestReleaseDate.AddDays(-$Days))) ) {
        # If we found the latest release date online and the installed version is more than [x] days older than it:
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        Write-Information -MessageData $LatestReleaseInfo -InformationAction Continue
        $IsRecentVersion = $false
    }
    elseif ( $InstalledVersionReleaseDate -le $OutOfDateDate ) {
        # If we didn't get the latest release date online, use the estimated release date to check age.
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        $IsRecentVersion = $false
    }
    else {
        # The installed version has not been found to be out of date.
        $IsRecentVersion = $True
    }

    # Return true/false
    $IsRecentVersion
}

function Test-IsRSATInstalled {
    <#
    .SYNOPSIS
        Tests if the RSAT AD PowerShell module is installed.
    .DESCRIPTION
        This function returns True if the RSAT AD PowerShell module is installed or False if not.
    .EXAMPLE
        Test-IsElevated
    #>
    if (Get-Module -Name 'ActiveDirectory' -ListAvailable) {
        $true
    }
    else {
        $false
    }
}
function Update-ESC1Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC1 issues.

    .DESCRIPTION
        This function takes a single ESC1 issue as input then asks a series of questions to determine the correct
        remediation.

        Questions:
        1. Does the identified principal need to enroll in this template? [Yes/No/Unsure]
        2. Is this certificate widely used and/or frequently requested? [Yes/No/Unsure]

        Depending on answers to these questions, the Issue and Fix attributes on the Issue object are updated.

        TODO: More questions:
        Should the identified principal be able to request certs that include a SAN or SANs?

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC1 issue.

    .OUTPUTS
        This function updates ESC1 remediations customized to the user's needs.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ESC1Issues = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        foreach ($issue in $ESC1Issues) { Update-ESC1Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Issue
    )

    $Header = "`n[!] ESC1 Issue detected in $($Issue.Name)"
    Write-Host $Header -ForegroundColor Yellow
    Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
    Write-Host "$($Issue.IdentityReference) can provide a Subject Alternative Name (SAN) while enrolling in this"
    Write-Host "template. Manager approval is not required for a certificate to be issued.`n"
    Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

    $Enroll = ''
    do {
        $Enroll = Read-Host "`n[?] Does $($Issue.IdentityReference) need to Enroll in the $($Issue.Name) template? [y/n/unsure]"
    } while ( ($Enroll -ne 'y') -and ($Enroll -ne 'n') -and ($Enroll -ne 'unsure'))

    if ($Enroll -eq 'y') {
        $Frequent = ''
        do {
            $Frequent = Read-Host "`n[?] Is the $($Issue.Name) certificate frequently requested? [y/n/unsure]"
        } while ( ($Frequent -ne 'y') -and ($Frequent -ne 'n') -and ($Frequent -ne 'unsure'))

        if ($Frequent -ne 'n') {
            $Issue.Fix = @"
# Locksmith cannot currently determine the best remediation course.
# Remediation Options:
# 1. If $($Issue.IdentityReference) is a group, remove its Enroll/AutoEnroll rights and grant those rights
#   to a smaller group or a single user/service account.

# 2. Remove the ability to submit a SAN (aka disable "Supply in the request").
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}

# 3. Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@

            $Issue.Revert = @"
# 1. Replace Enroll/AutoEnroll rights from the smaller group/single user/service account and grant those rights
#   back to $($Issue.IdentityReference).

# 2. Restore the ability to submit a SAN.
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}

# 3. Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
        }
    }
    elseif ($Enroll -eq 'n') {
        $Issue.Fix = @"
<#
    1. Open the Certification Templates Console: certtmpl.msc
    2. Double-click the $($Issue.Name) template to open its Properties page.
    3. Select the Security tab.
    4. Select the entry for $($Issue.IdentityReference).
    5. Uncheck the "Enroll" and/or "Autoenroll" boxes.
    6. Click OK.
#>
"@

        $Issue.Revert = @"
<#
    1. Open the Certification Templates Console: certtmpl.msc
    2. Double-click the $($Issue.Name) template to open its Properties page.
    3. Select the Security tab.
    4. Select the entry for $($Issue.IdentityReference).
    5. Check the "Enroll" and/or "Autoenroll" boxes depending on your specific needs.
    6. Click OK.
#>
"@
    } # end if ($Enroll -eq 'y')/elseif ($Enroll -eq 'n')
}

function Update-ESC4Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC4 issues.

    .DESCRIPTION
        This function takes a single ESC4 issue as input. It then prompts the user if the principal with the ESC4 rights
        administers the template in question.
        If the principal is an admin of the template:
          - the Issue attribute is updated to indicate this configuration is expected
          - the Fix attribute for the issue is updated to indicate no remediation is needed
          - the Risk Value, Risk Name, and Risk Scoring Details are updated to indicate no risk
        If the the principal is not an admin of the template AND the rights assigned is GenericAll, Locksmith will ask
        if Enroll or AutoEnroll rights are needed.
        Depending on the answers to the listed questions, the Fix attribute is updated accordingly.

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC4 issue.

    .OUTPUTS
        This function updates ESC4 remediations customized to the user's needs.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $ESC4Issues = Find-ESC4 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes -Mode 1
        foreach ($issue in $ESC4Issues) { Update-ESC4Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Issue
    )

    $Header = "`n[!] ESC4 Issue detected in $($Issue.Name)"
    Write-Host $Header -ForegroundColor Yellow
    Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
    Write-Host "$($Issue.IdentityReference) has $($Issue.ActiveDirectoryRights) rights on this template.`n"
    Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

    $Admin = ''
    do {
        $Admin = Read-Host "`n[?] Does $($Issue.IdentityReference) administer and/or maintain the $($Issue.Name) template? [y/n]"
    } while ( ($Admin -ne 'y') -and ($Admin -ne 'n') )

    if ($Admin -eq 'y') {
        $Issue.Issue = @"
$($Issue.IdentityReference) has $($Issue.ActiveDirectoryRights) rights on this template, but this is expected.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2
"@
        $Issue.Fix = "No immediate remediation required."
        $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue 0 -Force
        $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue 'Informational' -Force
        $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue "$($Issue.IdentityReference) administers this template" -Force
    }
    elseif ($Issue.Issue -match 'GenericAll') {
        $RightsToRestore = 0
        while ($RightsToRestore -notin 1..5) {
            [string]$Question = @"

Does $($Issue.IdentityReference) need to Enroll and/or AutoEnroll in the $($Issue.Name) template?

  1. Enroll
  2. AutoEnroll
  3. Both
  4. Neither
  5. Unsure

Enter your selection [1-5]
"@
            $RightsToRestore = Read-Host $Question
        }

        switch ($RightsToRestore) {
            1 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$NewRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$EnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$NewRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
            2 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$AutoEnrollGuid = [System.Guid]::New('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$AutoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$AutoEnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$AutoEnrollRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
            3 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$AutoEnrollGuid = [System.Guid]::New('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$EnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$EnrollGuid, `$InheritanceType
`$AutoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$AutoEnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$EnrollRule)
`$ACL.AddAccessRule(`$AutoEnrollRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
            4 {
                break 
            }
            5 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$AutoEnrollGuid = [System.Guid]::New('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$EnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$EnrollGuid, `$InheritanceType
`$AutoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$AutoEnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$EnrollRule)
`$ACL.AddAccessRule(`$AutoEnrollRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
        } # end switch ($RightsToRestore)
    } # end elseif ($Issue.Issue -match 'GenericAll')
}

function Update-ESC7Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC7 issues.

    .DESCRIPTION
        This function takes a single ESC7 issue as input. It then prompts the user if the principal with the ESC7 rights
        administers the Certification Authority (CA) in question.
        If the principal is an admin of the CA:
          - the Issue attribute is updated to indicate this configuration is expected
          - the Fix attribute for the issue is updated to indicate no remediation is needed
          - the Risk Value and Risk Scoring are set to
        If the the principal is not an admin of the CA,
        Depending on the answers to the listed questions, the Fix attribute is updated accordingly.

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC7 issue.

    .OUTPUTS
        This function updates ESC7 remediations customized to the user's needs.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $ESC7Issues = Find-ESC7 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes -Mode 1
        foreach ($issue in $ESC7Issues) { Update-ESC7Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Issue
    )

    if ($Issue.Right -eq 'CA Administrator') {
        $Header = "`n[!] ESC7 Issue detected on $($Issue.Name)"
        Write-Host $Header -ForegroundColor Yellow
        Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
        Write-Host "$($Issue.IdentityReference) has CA Administrator rights on this Certification Authority (CA).`n"
        Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

        $Admin = ''
        do {
            $Admin = Read-Host "`n[?] Does $($Issue.IdentityReference) administer and/or maintain the $($Issue.Name) CA? [y/n]"
        } while ( ($Admin -ne 'y') -and ($Admin -ne 'n') )

        if ($Admin -eq 'y') {
            $Issue.Issue = @"
$($Issue.IdentityReference) has CA Administrator rights on this CA, but this is expected.

Note:
These rights grant $($Issue.IdentityReference) control of the forest.
This principal should be considered a Tier 0/control plane object and protected as such.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
            $Issue.Fix = "No immediate remediation required."
            $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue 0 -Force
            $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue 'Informational' -Force
            $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue "$($Issue.IdentityReference) administers this CA" -Force
        }
    }

    if ($Issue.Right -eq 'Certificate Manager') {
        $Header = "`n[!] ESC7 Issue detected on $($Issue.Name)"
        Write-Host $Header -ForegroundColor Yellow
        Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
        Write-Host "$($Issue.IdentityReference) has Certificate Manager rights on this Certification Authority (CA).`n"
        Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

        $Admin = ''
        do {
            $Admin = Read-Host "`n[?] Does $($Issue.IdentityReference) need to approve pending certificate requests on the $($Issue.Name) CA? [y/n]"
        } while ( ($Admin -ne 'y') -and ($Admin -ne 'n') )

        if ($Admin -eq 'y') {
            $Issue.Issue = @"
$($Issue.IdentityReference) has Certificate Manager rights on this CA, but this is expected.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
            $Issue.Fix = "No immediate remediation required."
            $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue 0 -Force
            $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue 'Informational' -Force
            $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue "$($Issue.IdentityReference) approves pending certificate requests on this CA" -Force
        }
    }
}

function Update-ESC9Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC9 issues.

    .DESCRIPTION
        This function takes a single ESC9 issue as input then asks a series of questions to determine the correct
        remediation.

        Questions:
        1. Does the identified principal need to enroll in this template? [Yes/No/Unsure]
        2. Is this certificate widely used and/or frequently requested? [Yes/No/Unsure]

        Depending on answers to these questions, the Issue and Fix attributes on the Issue object are updated.

        TODO: More questions:
        Should the identified principal be able to request certs that include a SAN or SANs?

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC1 issue.

    .OUTPUTS
        This function updates ESC9 remediations customized to the user's needs.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ESC9Issues = Find-ESC9 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        foreach ($issue in $ESC9Issues) { Update-ESC9Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Issue
    )

    $Header = "`n[!] ESC9 Issue detected in $($Issue.Name)"
    Write-Host $Header -ForegroundColor Yellow
    Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
    Write-Host @"
The $($Issue.Name) template has the szOID_NTDS_CA_SECURITY_EXT security extension
disabled. Certificates issued from this template will not enforce strong
certificate binding. Manager approval is not required for a certificate to be issued.
To provide the most appropriate remediation for this issue, Locksmith will now
ask you a few questions.
"@

    $Enroll = ''
    do {
        $Enroll = Read-Host "`n[?] Does $($Issue.IdentityReference) need to Enroll in the $($Issue.Name) template? [y/n/unsure]"
    } while ( ($Enroll -ne 'y') -and ($Enroll -ne 'n') -and ($Enroll -ne 'unsure'))

    if ($Enroll -eq 'y') {
        $Frequent = ''
        do {
            $Frequent = Read-Host "`n[?] Is the $($Issue.Name) certificate frequently requested? [y/n/unsure]"
        } while ( ($Frequent -ne 'y') -and ($Frequent -ne 'n') -and ($Frequent -ne 'unsure'))

        if ($Frequent -ne 'n') {
            $Issue.Fix = @"
# Locksmith cannot currently determine the best remediation course.
# Remediation Options:
# 1. If $($Issue.IdentityReference) is a group, remove its Enroll/AutoEnroll rights and grant those rights
#   to a smaller group or a single user/service account.

# 2. Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}

# 3. Enable the szOID_NTDS_CA_SECURITY_EXT security extension.
TODO
"@

            $Issue.Revert = @"
# 1. Replace Enroll/AutoEnroll rights from the smaller group/single user/service account and grant those rights
#   back to $($Issue.IdentityReference).

# 2. Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}

# 3. Disable the szOID_NTDS_CA_SECURITY_EXT security extension.
TODO
"@
        }
    }
    elseif ($Enroll -eq 'n') {
        $Issue.Fix = @"
<#
    1. Open the Certification Templates Console: certtmpl.msc
    2. Double-click the $($Issue.Name) template to open its Properties page.
    3. Select the Security tab.
    4. Select the entry for $($Issue.IdentityReference).
    5. Uncheck the "Enroll" and/or "Autoenroll" boxes.
    6. Click OK.
#>
"@

        $Issue.Revert = @"
<#
    1. Open the Certification Templates Console: certtmpl.msc
    2. Double-click the $($Issue.Name) template to open its Properties page.
    3. Select the Security tab.
    4. Select the entry for $($Issue.IdentityReference).
    5. Check the "Enroll" and/or "Autoenroll" boxes depending on your specific needs.
    6. Click OK.
#>
"@
    } # end if ($Enroll -eq 'y')/elseif ($Enroll -eq 'n')
}

<#
  Prerequisites: PowerShell version 2 or above.
  License: MIT
  Author:  Michael Klement <mklement0@gmail.com>
  DOWNLOAD, from PowerShell version 3 or above:
    irm https://gist.github.com/mklement0/243ea8297e7db0e1c03a67ce4b1e765d/raw/Out-HostColored.ps1 | iex
  The above directly defines the function below in your session and offers guidance for making it available in future
  sessions too.

  Alternatively, download this file manually and dot-source it (e.g.: . /Out-HostColored.ps1)
  To learn what the function does:
    * see the next comment block
    * or, once downloaded, invoke the function with -? or pass its name to Get-Help.

#>

function Write-HostColorized {
    <#
    .SYNOPSIS
    Colors portions of the default host output that match given patterns.
    .DESCRIPTION
    Colors portions of the default-formatted host output based on either
    regular expressions or literal substrings, assuming the host is a console or
    supports colored output using console colors.
    Matching is restricted to a single line at a time, but coloring multiple
    matches on a given line is supported.
    Two basic syntax forms are supported:
      * Single-color, via -Pattern, -ForegroundColor and -BackgroundColor
      * Multi-color (color per pattern), via a hashtable (dictionary) passed to
        -PatternColorMap.
    Note: Since output is sent to the host rather than the pipeline, you cannot
          chain calls to this function.
    .PARAMETER Pattern
    One or more search patterns specifying what parts of the formatted
    representations of the input objects should be colored.
     * By default, these patterns are interpreted as regular expressions.
     * If -SimpleMatch is also specified, the patterns are interpreted as literal
       substrings.
    .PARAMETER ForegroundColor
    The foreground color to use for the matching portions.
    Defaults to yellow.
    .PARAMETER BackgroundColor
    The optional background color to use for the matching portions.
    .PARAMETER PatternColorMap
    A hashtable (dictionary) with one or more entries in the following format:
      <pattern-or-pattern-array> = <color-spec>
    <pattern-or-pattern-array> is either a single string or an array of strings
    specifying the regex pattern(s) or literal substring(s) (with -SimpleMatch)
    to match.
    NOTE: If you're specifying an array literally, you must enclose it in (...) or
          @(...), and the individual patterns must all be quoted; e.g.:
            @('foo', 'bar')
    <color-spec> is a string that contains either a foreground [ConsoleColor]
    color alone (e.g. 'red'), a combination with a background color separated by ","
    (e.g., 'red,white') or just a background color (e.g, ',white').
    NOTE: If *multiple* patterns stored in a given hashtable may match on a given
          line and you want the *first* matching pattern to "win" predictably, be
          sure to pass an [ordered] hashtable ([ordered] @{ Foo = 'red; ... })
    See the examples for a complete example.
    .PARAMETER CaseSensitive
    Matches the patterns case-sensitively.
    By default, matching is case-insensitive.
    .PARAMETER WholeLine
    Specifies that the entire line containing a match should be colored,
    not just the matching portion.
    .PARAMETER SimpleMatch
    Interprets the -Pattern argument(s) as a literal substrings to match rather
    than as regular expressions.
    .PARAMETER InputObject
    The input object(s) whose formatted representations to color selectively.
    Typically provided via the pipeline.
    .EXAMPLE
    'A fool and his money', 'foo bar' | Out-HostColored foo
    Prints the substring 'foo' in yellow in the two resulting output lines.
    .EXAMPLE
    Get-Date | Out-HostColored '\p{L}+' red white
    Outputs the current date with all tokens composed of letters (p{L}) only in red
    on a white background.
    .EXAMPLE
    Get-Date | Out-HostColored @{ '\p{L}+' = 'red,white' }
    Same as the previous example, only via the dictionary-based -PatternColorMap
    parameter (implied).
    .EXAMPLE
    'It ain''t easy being green.' | Out-HostColored @{ ('easy', 'green') = 'green'; '\bbe.+?\b' = 'black,yellow' }
    Prints the words 'easy' and 'green' in green, and the word 'being' in black on yellow.
    Note the need to enclose pattern array 'easy', 'green' in (...), which also necessitates
    quoting its element.
    .EXAMPLE
    Get-ChildItem | select Name | Out-HostColored -WholeLine -SimpleMatch .txt
    Highlight all text file names in green.
    .EXAMPLE
    'apples', 'kiwi', 'pears' | Out-HostColored '^a', 's$' blue
    Highlight all "A"s at the beginning and "S"s at the end of lines in blue.
    #>

    # === IMPORTANT:
    #   * At least for now, we remain PSv2-COMPATIBLE.
    #   * Thus:
    #     * no `[ordered]`, `::new()`, `[pscustomobject]`, ...
    #     * No implicit Boolean properties in [CmdletBinding()] and [Parameter()] attributes (`Mandatory` instead of just `Mandatory`)
    # ===

    [CmdletBinding(DefaultParameterSetName = 'SingleColor')]
    param(
        [Parameter(ParameterSetName = 'SingleColor', Position = 0, Mandatory)] [string[]] $Pattern,
        [Parameter(ParameterSetName = 'SingleColor', Position = 1)] [ConsoleColor] $ForegroundColor = [ConsoleColor]::Yellow,
        [Parameter(ParameterSetName = 'SingleColor', Position = 2)] [ConsoleColor] $BackgroundColor,
        [Parameter(ParameterSetName = 'PerPatternColor', Position = 0, Mandatory)] [System.Collections.IDictionary] $PatternColorMap,
        [Parameter(ValueFromPipeline = $True)] $InputObject,
        [switch] $WholeLine,
        [switch] $SimpleMatch,
        [switch] $CaseSensitive
    )

    begin {

        Set-StrictMode -Version 1

        if ($PSCmdlet.ParameterSetName -eq 'SingleColor') {

            # Translate the indiv. arguments into the dictionary format suppoorted
            # by -PatternColorMap, so we can process $PatternColorMap uniformly below.
            $PatternColorMap = @{
                $Pattern = $ForegroundColor, $BackgroundColor
            }
        }
        # Otherwise: $PSCmdlet.ParameterSetName -eq 'PerPatternColor', i.e. a dictionary
        #            mapping patterns to colors was direclty passed in $PatternColorMap

        try {

            # The options for the [regex] instances to create.
            # We precompile them for better performance with many input objects.
            [System.Text.RegularExpressions.RegexOptions] $reOpts =
            if ($CaseSensitive) {
                'Compiled, ExplicitCapture' 
            }
            else {
                'Compiled, ExplicitCapture, IgnoreCase' 
            }

            # Transform the dictionary:
            #  * Keys: Consolidate multiple patterns into a single one with alternation and
            #          construct a [regex] instance from it.
            #  * Values: Transform the "[foregroundColor],[backgroundColor]" strings into an arguments
            #            hashtable that can be used for splatting with Write-Host.
            $map = [ordered] @{ } # !! For stable results in repeated enumerations, use [ordered].
            # !! This matters when multiple patterns match on a given line, and also requires the
            # !! *caller* to pass an [ordered] hashtable to -PatternColorMap
            foreach ($entry in $PatternColorMap.GetEnumerator()) {

                # Create a Write-Host color-arguments hashtable for splatting.
                if ($entry.Value -is [array]) {
                    $fg, $bg = $entry.Value # [ConsoleColor[]], from the $PSCmdlet.ParameterSetName -eq 'SingleColor' case.
                }
                else {
                    $fg, $bg = $entry.Value -split ','
                }
                $colorArgs = @{ }
                if ($fg) {
                    $colorArgs['ForegroundColor'] = [ConsoleColor] $fg 
                }
                if ($bg) {
                    $colorArgs['BackgroundColor'] = [ConsoleColor] $bg 
                }

                # Consolidate the patterns into a single pattern with alternation ('|'),
                # escape the patterns if -SimpleMatch was passsed.
                $re = New-Object regex -Args `
                $(if ($SimpleMatch) {
                        ($entry.Key | ForEach-Object { [regex]::Escape($_) }) -join '|'
                    }
                    else {
                        ($entry.Key | ForEach-Object { '({0})' -f $_ }) -join '|'
                    }),
                $reOpts

                # Add the tansformed entry.
                $map[$re] = $colorArgs
            }
        }
        catch {
            throw 
        }

        # Construct the arguments to pass to Out-String.
        $htArgs = @{ Stream = $True }
        if ($PSBoundParameters.ContainsKey('InputObject')) {
            # !! Do not use `$null -eq $InputObject`, because PSv2 doesn't create this variable if the parameter wasn't bound.
            $htArgs.InputObject = $InputObject
        }

        # Construct the script block that is used in the steppable pipeline created
        # further below.
        $scriptCmd = {

            # Format the input objects with Out-String and output the results line
            # by line, then look for matches and color them.
            & $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\Out-String', 'Cmdlet') @htArgs | ForEach-Object {

                # Match the input line against all regexes and collect the results.
                $matchInfos = :patternLoop foreach ($entry in $map.GetEnumerator()) {
                    foreach ($m in $entry.Key.Matches($_)) {
                        @{ Index = $m.Index; Text = $m.Value; ColorArgs = $entry.Value }
                        if ($WholeLine) {
                            break patternLoop 
                        }
                    }
                }

                # # Activate this for debugging.
                # $matchInfos | Sort-Object { $_.Index } | Out-String | Write-Verbose -vb

                if (-not $matchInfos) {
                    # No match found - output uncolored.
                    Write-Host -NoNewline $_
                }
                elseif ($WholeLine) {
                    # Whole line should be colored: Use the first match's color
                    $colorArgs = $matchInfos.ColorArgs
                    Write-Host -NoNewline @colorArgs $_
                }
                else {
                    # Parts of the line must be colored:
                    # Process the matches in ascending order of start position.
                    $offset = 0
                    foreach ($mi in $matchInfos | Sort-Object { $_.Index }) {
                        # !! Use of a script-block parameter is REQUIRED in WinPSv5.1-, because hashtable entries cannot be referred to like properties, unlinke in PSv7+
                        if ($mi.Index -lt $offset) {
                            # Ignore subsequent matches that overlap with previous ones whose colored output was already produced.
                            continue
                        }
                        elseif ($offset -lt $mi.Index) {
                            # Output the part *before* the match uncolored.
                            Write-Host -NoNewline $_.Substring($offset, $mi.Index - $offset)
                        }
                        $offset = $mi.Index + $mi.Text.Length
                        # Output the match at hand colored.
                        $colorArgs = $mi.ColorArgs
                        Write-Host -NoNewline @colorArgs $mi.Text
                    }
                    # Print any remaining part of the line uncolored.
                    if ($offset -lt $_.Length) {
                        Write-Host -NoNewline $_.Substring($offset)
                    }
                }
                Write-Host '' # Terminate the current output line with a newline - this also serves to reset the console's colors on Unix.
            }
        }

        # Create the script block as a *steppable pipeline*, which enables
        # to perform regular streaming pipeline processing, without having to collect
        # everything in memory first.
        $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
        $steppablePipeline.Begin($PSCmdlet)
    } # begin

    process {
        $steppablePipeline.Process($_)
    }

    end {
        $steppablePipeline.End()
    }
}

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

    $Version = '2026.1.4.1426'
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
    }
    else {
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
    }
    else {
        $Targets = Get-Target
    }

    Write-Host "Gathering AD CS Objects from $($Targets)..."
    if ($Credential) {
        $ADCSObjects = Get-ADCSObject -Targets $Targets -Credential $Credential
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -Credential $Credential -ForestGC $ForestGC
        $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential -ForestGC $ForestGC
        $ADCSObjects += $CAHosts
    }
    else {
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
            }
            catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        3 {
            $Output = Join-Path -Path $OutputPath -ChildPath "$FilePrefix ADCSRemediation.CSV"
            Write-Host "Writing AD CS issues to $Output..."
            try {
                $AllIssues | Select-Object Forest, Technique, Name, DistinguishedName, Issue, Fix, @{l = 'Risk'; e = { $_.RiskName } }, @{l = 'Risk Score'; e = { $_.RiskValue } }, @{l = 'Risk Score Detail'; e = { $_.RiskScoring -join "`n" } } | Export-Csv -NoTypeInformation $Output
                Write-Host "$Output created successfully!`n"
            }
            catch {
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


Invoke-Locksmith -Mode $Mode -Scans $Scans
