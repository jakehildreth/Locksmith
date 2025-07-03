<#
    .SYNOPSIS
    Converts a secure Active Directory Certificate Services (AD CS) environment to
    an insecure AD CS environment to the purposes of testing.

    .DESCRIPTION
    TSS reconfigures Certificate Authorities and creates
    users, templates, and objects necessary to test AD CS tools.

    .INPUTS
    None. You can't pipe objects to Invoke-TSS.ps1.

    .OUTPUTS
    None. Invoke-TSS.ps1 doesn't generate any output.
#>

#requires -Modules ActiveDirectory

Write-Output @'
 _______         _   _           _
|__   __|       | | (_)         | |
   | | __ _  ___| |_ _  ___ __ _| |
   | |/ _` |/ __| __| |/ __/ _` | |
   | | (_| | (__| |_| | (_| (_| | |
   |_|\__,_|\___|\__|_|\___\__,_|_|
    / ____|                   | |
   | (___  _ __   ___  ___  __| |
    \___ \| '_ \ / _ \/ _ \/ _` |
    ____) | |_) |  __/  __/ (_| |
  _|_____/| .__/ \___|\___|\__,_|
 / ____|  | |
| (___ |_ |_| _ _   _  __ _ _ __ ___
 \___ \ / _` | | | |/ _` | '__/ _ \
 ____) | (_| | |_| | (_| | | |  __/
|_____/ \__, |\__,_|\__,_|_|  \___|
           | |
           |_|
                The UnLocksmith
'@

$NewTemplates = @(
    'ESC1and2AutoEnroll'
    'ESC1and2Enroll'
    'ESC1and2FilteredAutoEnroll'
    'ESC1and2FilteredEnroll'
    'ESC1AutoEnroll'
    'ESC1Enroll'
    'ESC1FilteredAutoEnroll'
    'ESC1FilteredEnroll'
    'ESC2AutoEnroll'
    'ESC2Enroll'
    'ESC2FilteredAutoEnroll'
    'ESC2FilteredEnroll'
    'ESC3Condition1'
    'ESC3Condition2Schema1'
    'ESC3Condition2Schema2'
    'ESC4FilteredAutoEnroll'
    'ESC4FilteredEnroll'
    'ESC4FilteredOwner'
    'ESC4FilteredSafeUsers'
    'ESC4GenericAll'
    'ESC4UnsafeOwner'
    'ESC4WriteProperty'
    'ESC4WriteOwner'
)

$NewObjects = @(
    'ESC5FilteredAutoEnroll'
    'ESC5FilteredEnroll'
    'ESC5FilteredOwner'
    'ESC5FilteredSafeUsers'
    'ESC5GenericAll'
    'ESC5UnsafeOwner'
    'ESC5WriteProperty'
    'ESC5WriteOwner'
)

$Administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$AuthenticatedUsers = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')

$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$GenericAll = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$GenericRead = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
$ReadProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
$WriteOwner = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
$WriteProperty = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

$DefaultRights = $ExtendedRight + $GenericRead + $ReadProperty + $WriteProperty

$EnrollGUID = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AutoEnrollGUID = [GUID]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

$Allow = [System.Security.AccessControl.AccessControlType]::Allow

$PKSContainer = "CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).defaultNamingContext)"

$NewTemplates | ForEach-Object {
    New-ADObject -Name $_ -Type 'pKICertificateTemplate' -Path "CN=Certificate Templates,$PKSContainer"
}

$NewObjects | ForEach-Object {
    New-ADObject -Name $_ -Type 'container' -Path $PKSContainer
}

$ESC1and2AutoEnroll = Get-ADObject "CN=ESC1and2AutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1and2AutoEnrollProperties = @{
    'DisplayName'                 = 'ESC1and2AutoEnroll'
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '2.5.29.37.0'
}
Set-ADObject $ESC1and2AutoEnroll.DistinguishedName -Add $ESC1and2AutoEnrollProperties
$ACL = Get-Acl "AD:$ESC1and2AutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1and2AutoEnroll" -AclObject $ACL

$ESC1and2Enroll = Get-ADObject "CN=ESC1and2Enroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1and2EnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '2.5.29.37.0'
}
Set-ADObject $ESC1and2Enroll.DistinguishedName -Add $ESC1and2EnrollProperties
$ACL = Get-Acl "AD:$ESC1and2Enroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1and2Enroll" -AclObject $ACL

$ESC1and2FilteredAutoEnroll = Get-ADObject "CN=ESC1and2FilteredAutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1and2FilteredAutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '2.5.29.37.0'
}
Set-ADObject $ESC1and2FilteredAutoEnroll.DistinguishedName -Add $ESC1and2FilteredAutoEnrollProperties
$ACL = Get-Acl "AD:$ESC1and2FilteredAutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1and2FilteredAutoEnroll" -AclObject $ACL

$ESC1and2FilteredEnroll = Get-ADObject "CN=ESC1and2FilteredEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1and2FilteredEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '2.5.29.37.0'
}
Set-ADObject $ESC1and2FilteredEnroll.DistinguishedName -Add $ESC1and2FilteredEnrollProperties
$ACL = Get-Acl "AD:$ESC1and2FilteredEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1and2FilteredEnroll" -AclObject $ACL

$ESC1AutoEnroll = Get-ADObject "CN=ESC1AutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1AutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '1.3.6.1.5.5.7.3.2'
}
Set-ADObject $ESC1AutoEnroll.DistinguishedName -Add $ESC1AutoEnrollProperties
$ACL = Get-Acl "AD:$ESC1AutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1AutoEnroll" -AclObject $ACL

$ESC1Enroll = Get-ADObject "CN=ESC1Enroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1EnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '1.3.6.1.5.5.7.3.2'
}
Set-ADObject $ESC1Enroll.DistinguishedName -Add $ESC1EnrollProperties
$ACL = Get-Acl "AD:$ESC1Enroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1Enroll" -AclObject $ACL

$ESC1FilteredAutoEnroll = Get-ADObject "CN=ESC1FilteredAutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1FilteredAutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '1.3.6.1.5.5.7.3.2'
}
Set-ADObject $ESC1FilteredAutoEnroll.DistinguishedName -Add $ESC1FilteredAutoEnrollProperties
$ACL = Get-Acl "AD:$ESC1FilteredAutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1FilteredAutoEnroll" -AclObject $ACL

$ESC1FilteredEnroll = Get-ADObject "CN=ESC1FilteredEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1FilteredEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'pKIExtendedKeyUsage'         = '1.3.6.1.5.5.7.3.2'
}
Set-ADObject $ESC1FilteredEnroll.DistinguishedName -Add $ESC1FilteredEnrollProperties
$ACL = Get-Acl "AD:$ESC1FilteredEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1FilteredEnroll" -AclObject $ACL

$ESC2AutoEnroll = Get-ADObject "CN=ESC2AutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC2AutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
}
Set-ADObject $ESC2AutoEnroll.DistinguishedName -Add $ESC2AutoEnrollProperties
Set-ADObject $ESC2AutoEnroll.DistinguishedName -Clear pKIExtendedKeyUsage
$ACL = Get-Acl "AD:$ESC2AutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC2AutoEnroll" -AclObject $ACL

$ESC2Enroll = Get-ADObject "CN=ESC2Enroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC2EnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
}
Set-ADObject $ESC2Enroll.DistinguishedName -Add $ESC2EnrollProperties
Set-ADObject $ESC2Enroll.DistinguishedName -Clear pKIExtendedKeyUsage
$ACL = Get-Acl "AD:$ESC2Enroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC2Enroll" -AclObject $ACL

$ESC2FilteredAutoEnroll = Get-ADObject "CN=ESC2FilteredAutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC2FilteredAutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
}
Set-ADObject $ESC2FilteredAutoEnroll.DistinguishedName -Add $ESC2FilteredAutoEnrollProperties
Set-ADObject $ESC2FilteredAutoEnroll.DistinguishedName -Clear pKIExtendedKeyUsage
$ACL = Get-Acl "AD:$ESC2FilteredAutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC2FilteredAutoEnroll" -AclObject $ACL

$ESC2FilteredEnroll = Get-ADObject "CN=ESC2FilteredEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC2FilteredEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
}
Set-ADObject $ESC2FilteredEnroll.DistinguishedName -Add $ESC2FilteredEnrollProperties
Set-ADObject $ESC2FilteredEnroll.DistinguishedName -Clear pKIExtendedKeyUsage
$ACL = Get-Acl "AD:$ESC2FilteredEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC2FilteredEnroll" -AclObject $ACL

$ESC3Condition1 = Get-ADObject "CN=ESC3Condition1,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC3Condition1Properties = @{
    'DisplayName'                          = 'ESC3Condition1'
    'msPKI-Enrollment-Flag'                = 0
    'msPKI-Certificate-Application-Policy' = '1.3.6.1.4.1.311.20.2.1'
    'msPKI-Certificate-Name-Flag'          =	-2113929216
    # 'msPKI-Cert-Template-OID' = '1.3.6.1.4.1.311.21.8.11772860.15111666.14435736.6562275.12440657.32.7694220.3484220'
    #'msPKI-Minimal-Key-Size' = 2048
    #'msPKI-Private-Key-Flag' = 16842752
    'msPKI-RA-Signature'                   = 0
    # 'msPKI-Template-Minor-Revision'	= 7
    'msPKI-Template-Schema-Version'        = 2
    'pKIExtendedKeyUsage'                  = '1.3.6.1.4.1.311.20.2.1'
}
Set-ADObject $ESC3Condition1.DistinguishedName -Add $ESC3Condition1Properties
$ACL = Get-Acl "AD:$ESC3Condition1"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC3Condition1" -AclObject $ACL

# $ESC3Condition2Schema1 = Get-ADObject "CN=ESC3Condition2Schema1,CN=Certificate Templates,$PKSContainer" -Properties *
# $ESC3Condition2Schema1Properties = @{
#     'msPKI-Certificate-Name-Flag' = 1
#     'msPKI-Enrollment-Flag' = 0
#     'msPKI-RA-Signature' = 1
#     # 'msPKI-Certificate-Application-Policy' = ''
# }
# Set-ADObject $ESC3Condition2Schema1.DistinguishedName -Add $ESC3Condition2Schema1Properties
# Set-ADObject $ESC3Condition2Schema1.DistinguishedName -Clear pKIExtendedKeyUsage
# $ACL = Get-Acl "AD:$ESC3Condition2Schema1"
# $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
# $ACL.AddAccessRule($AccessRule)
# Set-Acl "AD:$ESC3Condition2Schema1" -AclObject $ACL

# $CertificateApplicationPolicies = @()
# $CertificateApplicationPolicies = @(
#     '1.3.6.1.4.1.311.10.3.4'
#     '1.3.6.1.5.5.7.3.4'
#     '1.3.6.1.5.5.7.3.2'
# )

# $ESC3Condition2Schema2 = Get-ADObject "CN=ESC3Condition2Schema2,CN=Certificate Templates,$PKSContainer" -Properties *
# $ESC3Condition2Schema2Properties = @{
#     'msPKI-Certificate-Name-Flag' = 1
#     'msPKI-Enrollment-Flag' = 0
#     'msPKI-RA-Application-Policies' = '1.3.6.1.4.1.311.20.2.1'
#     'msPKI-RA-Signature' = 1
#     # 'msPKI-Certificate-Application-Policies' = $CertificateApplicationPolicies
#     'msPKI-Cert-Template-OID'	= '1.3.6.1.4.1.311.21.8.11772860.15111666.14435736.6562275.12440657.32.14251779.12149136'
#     'msPKI-Minimal-Key-Size' = 2048
#     'msPKI-Private-Key-Flag' = 16842768
#     'msPKI-Template-Minor-Revision' = 18
#     'msPKI-Template-Schema-Version' = 2
# }
# Set-ADObject $ESC3Condition2Schema2.DistinguishedName -Add $ESC3Condition2Schema2Properties
# Set-ADObject $ESC3Condition2Schema2.DistinguishedName -Clear pKIExtendedKeyUsage
# $ACL = Get-Acl "AD:$ESC3Condition2Schema2"
# $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
# $ACL.AddAccessRule($AccessRule)
# Set-Acl "AD:$ESC3Condition2Schema2" -AclObject $ACL

$ESC4FilteredAutoEnroll = Get-ADObject "CN=ESC4FilteredAutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4FilteredAutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4FilteredAutoEnroll" -AclObject $ACL

$ESC4FilteredEnroll = Get-ADObject "CN=ESC4FilteredEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4FilteredEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4FilteredEnroll" -AclObject $ACL

$ESC4FilteredOwner = Get-ADObject "CN=ESC4FilteredOwner,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4FilteredOwner"
$ACL.SetOwner($Administrators)
Set-Acl "AD:$ESC4FilteredOwner" -AclObject $ACL

$ESC4FilteredSafeUsers = Get-ADObject "CN=ESC4FilteredSafeUsers,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4FilteredSafeUsers"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $GenericAll, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4FilteredSafeUsers" -AclObject $ACL

$ESC4GenericAll = Get-ADObject "CN=ESC4GenericAll,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4GenericAll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $GenericAll, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4GenericAll" -AclObject $ACL

$ESC4UnsafeOwner = Get-ADObject "CN=ESC4UnsafeOwner,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4UnsafeOwner"
$ACL.SetOwner($AuthenticatedUsers)
Set-Acl "AD:$ESC4UnsafeOwner" -AclObject $ACL

$ESC4WriteProperty = Get-ADObject "CN=ESC4WriteProperty,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4WriteProperty"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $WriteProperty, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4WriteProperty" -AclObject $ACL

$ESC4WriteOwner = Get-ADObject "CN=ESC4WriteOwner,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4WriteOwner"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $WriteOwner, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4WriteOwner" -AclObject $ACL

$ESC5FilteredAutoEnroll = Get-ADObject "CN=ESC5FilteredAutoEnroll,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5FilteredAutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5FilteredAutoEnroll" -AclObject $ACL

$ESC5FilteredEnroll = Get-ADObject "CN=ESC5FilteredEnroll,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5FilteredEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $DefaultRights, $Allow, $EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5FilteredEnroll" -AclObject $ACL

$ESC5FilteredOwner = Get-ADObject "CN=ESC5FilteredOwner,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5FilteredOwner"
$ACL.SetOwner($Administrators)
Set-Acl "AD:$ESC5FilteredOwner" -AclObject $ACL

$ESC5FilteredSafeUsers = Get-ADObject "CN=ESC5FilteredSafeUsers,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5FilteredSafeUsers"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Administrators, $GenericAll, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5FilteredSafeUsers" -AclObject $ACL

$ESC5GenericAll = Get-ADObject "CN=ESC5GenericAll,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5GenericAll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $GenericAll, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5GenericAll" -AclObject $ACL

$ESC5UnsafeOwner = Get-ADObject "CN=ESC5UnsafeOwner,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5UnsafeOwner"
$ACL.SetOwner($AuthenticatedUsers)
Set-Acl "AD:$ESC5UnsafeOwner" -AclObject $ACL

$ESC5WriteProperty = Get-ADObject "CN=ESC5WriteProperty,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5WriteProperty"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $WriteProperty, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5WriteProperty" -AclObject $ACL

$ESC5WriteOwner = Get-ADObject "CN=ESC5WriteOwner,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5WriteOwner"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers, $WriteOwner, $Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5WriteOwner" -AclObject $ACL

Get-ADObject -Filter 'objectClass -eq "pKIEnrollmentService"' -SearchBase $PKSContainer -Properties * | ForEach-Object {
    $ForestGC = $(Get-ADDomainController -Discover -Service GlobalCatalog -ForceDiscover | Select-Object -ExpandProperty Hostname) + ':3268'
    [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
    $CAHostname = $_.dNSHostName.split('.')[0]
    $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC).DnsHostname
    $ping = Test-Connection -ComputerName $CAHostFQDN -Quiet
    if ($ping) {
        try {
            $CertutilAudit = certutil -config $CAFullName -getreg CA\AuditFilter
        } catch {
            $AuditFilter = 'Failure'
        }
        try {
            $CertutilFlag = certutil -config $CAFullName -getreg policy\EditFlags
        } catch {
            $AuditFilter = 'Failure'
        }
        try {
            $CertutilInterfaceFlag = certutil -config $CAFullName -getreg CA\InterfaceFlags
        } catch {
            $CertutilInterfaceFlag = 'Failure'
        }
    } else {
        $AuditFilter = 'CA Unavailable'
        $SANFlag = 'CA Unavailable'
        $InterfaceFlag = 'CA Unavailable'
    }
    if ($CertutilAudit) {
        try {
            [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
            $AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
        } catch {
            try {
                [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
                $AuditFilter = $AuditFilter.split('=')[1].trim()
            } catch {
                $AuditFilter = 'Never Configured'
            }
        }
    }
    if ($CertutilFlag) {
        [string]$SANFlag = $CertutilFlag | Select-String ' EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 \('
        if ($SANFlag) {
            $SANFlag = 'Yes'
        } else {
            $SANFlag = 'No'
        }
    }
    if ($CertutilInterfaceFlag) {
        [string]$InterfaceFlag = $CertutilInterfaceFlag | Select-String ' IF_ENFORCEENCRYPTICERTREQUEST -- 200 \('
        if ($InterfaceFlag) {
            $InterfaceFlag = 'Yes'
        } else {
            $InterfaceFlag = 'No'
        }
    }

    if ( ($AuditFilter -ne '0') -and ($AuditFilter -ne 'Never Configured') ) {
        certutil -config $CAFullname -setreg CA\AuditFilter 0
        Invoke-Command -ComputerName $CAHostFQDN -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
    }

    if ($SANFlag -eq 'No') {
        certutil -config $CAFullname -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
        Invoke-Command -ComputerName $CAHostFQDN -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
    }

    if ($InterfaceFlag -eq 'Yes') {
        certutil -config $CAFullname -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST
        Invoke-Command -ComputerName $CAHostFQDN -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
    }
}
