[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The helpers only build test objects.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'The host names are fake test data.')]
param()

# Shared helpers for the tests that need a CA object. Dot-source this file from BeforeAll.
# The real type comes with RSAT. Tests that use these helpers skip on a machine without it.

function New-TestADEntity {
    param([hashtable]$Property = @{})
    $entityType = 'Microsoft.ActiveDirectory.Management.ADEntity' -as [type]
    $entity = try { $entityType::new() } catch { New-Object -TypeName Microsoft.ActiveDirectory.Management.ADObject }
    foreach ($key in $Property.Keys) {
        Add-Member -InputObject $entity -MemberType NoteProperty -Name $key -Value $Property[$key] -Force
    }
    $entity
}

function New-TestStageResult {
    param(
        [bool]$Dns = $true,
        [bool]$Icmp = $true,
        [bool]$Transport = $true,
        [bool]$Certutil = $true,
        $HResult = $null
    )
    [pscustomobject]@{
        DNS       = [pscustomobject]@{ Passed = $Dns; ElapsedMs = 1; Detail = 'x' }
        ICMP      = [pscustomobject]@{ Passed = $Icmp; ElapsedMs = 1; Detail = 'x' }
        Transport = [pscustomobject]@{ Passed = $Transport; ElapsedMs = 1; Detail = 'x'; Port = 135 }
        Certutil  = [pscustomobject]@{ Passed = $Certutil; ElapsedMs = 1; Detail = 'certutil said this'; HResult = $HResult; TimedOut = $false; RemoteError = $false }
    }
}

# A healthy CA by default. Pass a hashtable to change any property.
function New-TestCA {
    param(
        [string]$Name = 'CA1',
        [hashtable]$Property = @{}
    )
    $values = @{
        objectClass             = 'pKIEnrollmentService'
        Name                    = $Name
        dNSHostName             = 'ca1.corp.example'
        CanonicalName           = "corp.example/Configuration/Services/Public Key Services/Enrollment Services/$Name"
        DistinguishedName       = "CN=$Name,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example"
        CAFullName              = "ca1.corp.example\$Name"
        CAHostDistinguishedName = 'CN=CA1,OU=Servers,DC=corp,DC=example'
        CAEnrollmentEndpoint    = @()
        Reachable               = $true
        CAStageResult           = New-TestStageResult
        CAUnavailabilityReason  = $null
        CAReadFailure           = @{}
        AuditFilter             = '127'
        SANFlag                 = 'No'
        InterfaceFlag           = 'Yes'
        DisableExtensionList    = 'No'
        CAAdministrator         = @()
        CertificateManager      = @()
    }
    foreach ($key in $Property.Keys) {
        $values[$key] = $Property[$key]
    }
    New-TestADEntity -Property $values
}

# A CA that did not answer the certutil ping. Every value is null, as Set-AdditionalCAProperty leaves it.
function New-TestUnreachableCA {
    param([string]$Name = 'CA1')
    $stages = New-TestStageResult -Certutil $false -HResult ([int]0x800706ba) -Icmp $false
    New-TestCA -Name $Name -Property @{
        Reachable              = $false
        CAStageResult          = $stages
        CAUnavailabilityReason = Get-CAUnavailabilityReason -StageResult $stages -ComputerName 'ca1.corp.example'
        AuditFilter            = $null
        SANFlag                = $null
        InterfaceFlag          = $null
        DisableExtensionList   = $null
        CAAdministrator        = $null
        CertificateManager     = $null
    }
}
