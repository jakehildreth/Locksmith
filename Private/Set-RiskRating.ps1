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
        A PSCustomObject that includes all pertinent information about an AD CS ssue.

        .INPUTS
        PSCustomObject

        .OUTPUTS
        None. This function sets a new attribute on each Issue object and returns nothing to the pipeline.

        .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $ESC4Issues = Find-ESC4 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes -Mode 1
        foreach ($issue in $ESC4Issues) { Set-RiskRating -Issue $Issue }

        .LINK
    #>
    [CmdletBinding()]
    param (
        $Issue
    )

    #requires -Version 5

    $RiskValue = 0
    $RiskName = ''

    # The principal's objectClass impacts the Issue's risk
    if ($Issue.Technique -notin @('DETECT','ESC6','ESC8','ESC11')) {
        $SID = $Issue.IdentityReferenceSID.ToString()
        $IdentityReferenceObjectClass = Get-ADObject -Filter { objectSid -eq $SID }  | Select-Object objectClass
    }

    # CA issues don't rely on a principal and have a base risk of Medium.
    if ($Issue.Technique -in @('DETECT','ESC6','ESC8','ESC11')) {
        $RiskValue += 3
    }

    # Templates are more dangerous when enabled.
    if ($Issue.Technique -in @('ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC13', 'ESC15')) {
        if ($Issue.Enabled) {
            $RiskValue += 1
        } else {
            $RiskValue -= 1
        }
    }

    # ESC1 and ESC4 templates are more dangerous than other templates because they can result in immediate compromise.
    if ($Issue.Technique -in @('ESC1','ESC4')) {
        $RiskValue += 1
    }

    if ($Issue.IdentityReferenceSID -match $UnsafeUsers) {
        # Authenticated Users, Domain Users, Domain Computers etc. are very risky
        $RiskValue += 2
    } elseif ($IdentityReferenceObjectClass -eq 'group') {
        # Groups are riskier than individual principals
        $RiskValue += 1
    }

    # Safe users and managed service accounts are inherently safer than other principals.
    if ($Issue.IdentityReferenceSID -notmatch $SafeUsers -and $IdentityReferenceObjectClass -notlike '*ManagedServiceAccount') {
        $RiskValue += 1
    }

    # Convert Value to Name
    $RiskName = switch ($RiskValue) {
        { $_ -le 1 } { 'Informational' }
        2            { 'Low' }
        3            { 'Medium' }
        4            { 'High' }
        { $_ -ge 5 } { 'Critical' }
    }

    # Write Risk attributes
    $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue $RiskValue -Force
    $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue $RiskName -Force
}
