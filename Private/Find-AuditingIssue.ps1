function Find-AuditingIssue {
    <#
    .SYNOPSIS
        A function to find auditing issues on AD CS CAs.

    .DESCRIPTION
        This script takes an array of AD CS objects and filters them based on specific criteria to identify auditing issues.
        It checks if the object's objectClass is 'pKIEnrollmentService' and if the AuditFilter is not null and not equal to '127'.
        For each matching object, it creates a custom object with information about the issue, fix, and revert actions.
        A CA whose AuditFilter is null (not Reachable, or the read failed) is skipped. Find-AvailabilityIssue reports it.

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
        ($null -ne $_.AuditFilter) -and
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
        if ($SkipRisk -eq $false) {
            Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
        }
        $Issue
    }
}
