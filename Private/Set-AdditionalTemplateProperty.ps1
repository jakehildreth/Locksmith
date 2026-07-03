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
            }
            $template | Add-Member -NotePropertyName Enabled -NotePropertyValue $Enabled -Force
            $template | Add-Member -NotePropertyName EnabledOn -NotePropertyValue $EnabledOn -Force
        }
    }
}
