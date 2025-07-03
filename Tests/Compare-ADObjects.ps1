# Source: https://learn.microsoft.com/en-us/archive/blogs/janesays/compare-all-properties-of-two-objects-in-windows-powershell
param(
    [Parameter(Mandatory)]
    [string]$DN1,
    [Parameter(Mandatory)]
    [string]$DN2
)
$ExcludedProperties = @(
    'CanonicalName'
    'CN'
    'Created'
    'createTimeStamp'
    'Description'
    'DisplayName'
    'DistinguishedName'
    'Modified'
    'modifyTimeStamp'
    'Name'
    'ObjectGUID'
    'uSNChanged'
    'uSNCreated'
    'whenChanged'
    'whenCreated'
)

$ReferenceObject = Get-ADObject -Identity $DN1 -Properties * | Select-Object -Property * -ExcludeProperty $ExcludedProperties
$DifferenceObject = Get-ADObject -Identity $DN2 -Properties * | Select-Object -Property * -ExcludeProperty $ExcludedProperties

$ObjectProperties = $ReferenceObject | Get-Member -MemberType Property, NoteProperty | ForEach-Object Name
$ObjectProperties += $DifferenceObject | Get-Member -MemberType Property, NoteProperty | ForEach-Object Name
$ObjectProperties = $ObjectProperties | Sort-Object | Select-Object -Unique
$Differences = @()

foreach ($objectproperty in $ObjectProperties) {
    $difference = Compare-Object $ReferenceObject $DifferenceObject -Property $objectproperty
    if ($difference) {
        $differenceproperties = @{
            PropertyName = $objectproperty
            RefValue     = ($difference | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object $($objectproperty))
            DiffValue    = ($difference | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object $($objectproperty))
        }
        $Differences += New-Object PSObject -Property $differenceproperties
    }
}
if ($Differences) {
    return (
        $Differences | Select-Object PropertyName, RefValue, DiffValue
    )
}
