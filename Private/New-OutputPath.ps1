function New-OutputPath {
    <#
    .SYNOPSIS
        Creates output directories for each forest.

    .DESCRIPTION
        Creates one output directory per forest specified in the Targets parameter.
        The output directories are created under the OutputPath directory.

    .PARAMETER Targets
        Specifies the forests for which output directories need to be created.

    .PARAMETER OutputPath
        Specifies the base path where the output directories will be created.

    .EXAMPLE
        New-OutputPath -Targets "Forest1", "Forest2" -OutputPath "C:\Output"
        This example creates two output directories named "Forest1" and "Forest2" under the "C:\Output" directory.

    #>

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [array]$Targets,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    foreach ($forest in $Targets) {
        $ForestPath = Join-Path -Path $OutputPath -ChildPath $forest
        if ($PSCmdlet.ShouldProcess($ForestPath, 'Create directory')) {
            New-Item -Path $ForestPath -ItemType Directory -Force | Out-Null
        }
    }
}
