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
    if ($Issue.Technique -in @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC16')) {
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
            } elseif ($IdentityReferenceObjectClass -eq 'group') {
                # Groups are riskier than individual principals
                $RiskValue += 1
                $RiskScoring += 'Group: +1'
            } elseif ($Issue.IdentityReferenceSID -notmatch $UnsafeUsers -and
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
    if ($Issue.Technique -notin @('DETECT', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC16')) {
        $RiskScoring += 'Base Score: 0'

        # Templates are more dangerous when enabled, but objects cannot be enabled/disabled.
        if ($Issue.Technique -ne 'ESC5') {
            if ($Issue.Enabled) {
                $RiskValue += 1
                $RiskScoring += 'Enabled: +1'
            } else {
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
        } elseif ($IdentityReferenceObjectClass -eq 'group') {
            # Groups are riskier than individual principals
            $RiskValue += 1
            $RiskScoring += 'Group: +1'
        } elseif ($Issue.IdentityReferenceSID -notmatch $UnsafeUsers -and
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
            } elseif ($IdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                # Managed Service Accounts are *probably* privileged in some way.
                $RiskValue += 1
                $RiskScoring += 'Managed Service Account: +1'
            }
        } elseif ($Issue.IdentityReferenceSID -notmatch $SafeUsers -and $IdentityReferenceObjectClass -notlike '*ManagedServiceAccount') {
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
                        } else {
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
                        } elseif ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups that contain practically all principals and likely including admins.
                            # Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        } elseif ($escIdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                            # Managed Service Accounts are *probably* privileged in some way.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
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
                        } else {
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
                        } elseif ($escSID -match $UnsafeUsers) {
                            # Unsafe Users are large groups that contain practically all principals and likely including admins.
                            # Authenticating as an admin is bad.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 2
                        } elseif ($escIdentityReferenceObjectClass -like '*ManagedServiceAccount') {
                            # Managed Service Accounts are *probably* privileged in some way.
                            $Principals += $esc.IdentityReference.Value
                            $OtherTemplateRisk += 1
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
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
                        } else {
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
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
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
                        } else {
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
                        } elseif ($escIdentityReferenceObjectClass -eq 'group') {
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
                        } else {
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
                        } elseif ($OtherIssueIdentityReferenceObjectClass -eq 'group') {
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
                'certificationAuthority' { $RiskValue += 2; $RiskScoring += 'Root Certification Authority bject: +2' }
                # Being able to modify Issuing CA Objects is also very bad.
                'pKIEnrollmentService' { $RiskValue += 2; $RiskScoring += 'Issuing Certification Authority Object: +2' }
                # Being able to modify CA Hosts? Yeah... very bad.
                'computer' { $RiskValue += 2; $RiskScoring += 'Certification Authority Host Computer: +2' }
                # Being able to modify OIDs could result in ESC13 vulns.
                'msPKI-Enterprise-Oid' { $RiskValue += 1; $RiskScoring += 'OID: +1' }
                # Being able to modify PKS containers is bad.
                'container' { $RiskValue += 1; $RiskScoring += 'Container: +1' }
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
        { $_ -le 1 } { 'Informational' ; break }
        { $_ -lt 3 } { 'Low' ; break }
        { $_ -lt 4 } { 'Medium' ; break }
        { $_ -lt 5 } { 'High' ; break }
        { $_ -ge 5 } { 'Critical' ; break }
    }

    # Write Risk attributes
    $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue $RiskValue -Force
    $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue $RiskName -Force
    $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue $RiskScoring -Force
}
