function Set-AdditionalCAProperty {
    <#
    .SYNOPSIS
        Sets additional properties for a Certificate Authority (CA) object.

    .DESCRIPTION
        This script sets additional properties for a Certificate Authority (CA) object.
        It takes an array of AD CS Objects as input, which represent the CA objects to be processed.
        The script filters the AD CS Objects based on the objectClass property and performs the necessary operations
        to set the additional properties.

        For each CA, it runs the Availability check (Test-CAAvailability) and adds these properties:
          - Reachable: true if and only if certutil -pingadmin succeeded.
          - CAStageResult: the result of each Stage (DNS, ICMP, Transport, Certutil).
          - CAUnavailabilityReason: why the CA is not Reachable, or null when it is.
          - CAReadFailure: a hashtable of value-property name to reason for each certutil -getreg read that failed.

        It then reads AuditFilter, SANFlag, InterfaceFlag, CAAdministrator, CertificateManager, and DisableExtensionList.
        A value is null when the CA is not Reachable or its read failed. It is never set to a message string.
        An absent registry value (0x80070002) is not a failed read, except for CA\Security, which always exists.
        Every CA starts with no values, so a CA never inherits the previous CA's data.

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
            } else {
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
                } catch {
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
                    } catch {
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
                        } catch {
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
            } else {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC ).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC).DnsHostname
            }
            $ComputerName = $CAHostFQDN
            if (-not $ComputerName) {
                Write-Warning "Unable to resolve $($_.Name) Fully Qualified Domain Name (FQDN)"
                $ComputerName = $_.dNSHostName
            }
            $AvailabilityParameters = @{
                CAFullName   = $CAFullName
                ComputerName = $ComputerName
            }
            if ($Credential) {
                $AvailabilityParameters.Credential = $Credential
            }
            $Availability = Test-CAAvailability @AvailabilityParameters

            # Every CA starts with no values, so an unavailable CA can never inherit the previous CA's data.
            $AuditFilter = $null
            $SANFlag = $null
            $InterfaceFlag = $null
            $CAAdministrator = $null
            $CertificateManager = $null
            $DisableExtensionList = $null
            $CAReadFailure = @{}
            $AuditRead = $null
            $FlagRead = $null
            $InterfaceRead = $null
            $SecurityRead = $null
            $DisableExtensionListRead = $null

            if ($Availability.Reachable) {
                $ReadParameters = @{
                    CAFullName   = $CAFullName
                    ComputerName = $ComputerName
                }
                if ($Credential) {
                    $ReadParameters.Credential = $Credential
                }
                $AuditRead = Invoke-CertutilGetReg @ReadParameters -Path 'CA\AuditFilter'
                $FlagRead = Invoke-CertutilGetReg @ReadParameters -Path 'policy\EditFlags'
                $InterfaceRead = Invoke-CertutilGetReg @ReadParameters -Path 'CA\InterfaceFlags'
                $SecurityRead = Invoke-CertutilGetReg @ReadParameters -Path 'CA\Security'
                $DisableExtensionListRead = Invoke-CertutilGetReg @ReadParameters -Path 'policy\DisableExtensionList'
            }

            # A read passes, or fails because the value was never set (0x80070002), or truly fails.
            # CA\Security always exists, so 0x80070002 there is a failed read.
            $ValueNotSet = [int]0x80070002
            $DescribeReadFailure = {
                param($Read)
                if ($Read.RemoteError) {
                    "Remote command failed: $($Read.Detail)"
                } elseif ($null -ne $Read.HResult) {
                    (Get-CAHResultReason -HResult ([int]$Read.HResult)).Text
                } else {
                    "Read failed: $($Read.Detail)"
                }
            }
            if ($AuditRead) {
                if ($AuditRead.Passed -or $AuditRead.HResult -eq $ValueNotSet) {
                    $CertutilAudit = if ($AuditRead.Passed) { $AuditRead.Output } else { @() }
                    try {
                        $AuditFilter = [string]($CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\(')
                        $AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
                    } catch {
                        try {
                            $AuditFilter = [string]($CertutilAudit | Select-String 'AuditFilter REG_DWORD = ')
                            $AuditFilter = $AuditFilter.split('=')[1].trim()
                        } catch {
                            $AuditFilter = 'Never Configured'
                        }
                    }
                } else {
                    $CAReadFailure['AuditFilter'] = & $DescribeReadFailure $AuditRead
                }
            }
            if ($FlagRead) {
                if ($FlagRead.Passed -or $FlagRead.HResult -eq $ValueNotSet) {
                    $CertutilFlag = if ($FlagRead.Passed) { $FlagRead.Output } else { @() }
                    $SANFlag = if ([string]($CertutilFlag | Select-String ' EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 \(')) { 'Yes' } else { 'No' }
                } else {
                    $CAReadFailure['SANFlag'] = & $DescribeReadFailure $FlagRead
                }
            }
            if ($InterfaceRead) {
                if ($InterfaceRead.Passed -or $InterfaceRead.HResult -eq $ValueNotSet) {
                    $CertutilInterfaceFlag = if ($InterfaceRead.Passed) { $InterfaceRead.Output } else { @() }
                    $InterfaceFlag = if ([string]($CertutilInterfaceFlag | Select-String ' IF_ENFORCEENCRYPTICERTREQUEST -- 200 \(')) { 'Yes' } else { 'No' }
                } else {
                    $CAReadFailure['InterfaceFlag'] = & $DescribeReadFailure $InterfaceRead
                }
            }
            if ($SecurityRead) {
                if ($SecurityRead.Passed) {
                    $CertutilSecurity = $SecurityRead.Output
                    $CAAdministrator = [string[]]@($CertutilSecurity | ForEach-Object {
                            if ($_ -match '^.*Allow.*CA Administrator.*.*\t(.*)$') {
                                $matches[1].ToString()
                            }
                        })
                    $CertificateManager = [string[]]@($CertutilSecurity | ForEach-Object {
                            if ($_ -match '^.*Allow.*Certificate Manager.*\t(.*)$') {
                                $matches[1].ToString()
                            }
                        })
                } else {
                    $CAReadFailure['CAAdministrator'] = & $DescribeReadFailure $SecurityRead
                    $CAReadFailure['CertificateManager'] = $CAReadFailure['CAAdministrator']
                }
            }
            if ($DisableExtensionListRead) {
                if ($DisableExtensionListRead.Passed -or $DisableExtensionListRead.HResult -eq $ValueNotSet) {
                    $CertutilDisableExtensionList = if ($DisableExtensionListRead.Passed) { $DisableExtensionListRead.Output } else { @() }
                    $DisableExtensionList = if ([string]($CertutilDisableExtensionList | Select-String '1\.3\.6\.1\.4\.1\.311\.25\.2')) { 'Yes' } else { 'No' }
                } else {
                    $CAReadFailure['DisableExtensionList'] = & $DescribeReadFailure $DisableExtensionListRead
                }
            }
            Add-Member -InputObject $_ -MemberType NoteProperty -Name Reachable -Value ([bool]$Availability.Reachable) -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAStageResult -Value $Availability.CAStageResult -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAUnavailabilityReason -Value $Availability.CAUnavailabilityReason -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAReadFailure -Value $CAReadFailure -Force
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
