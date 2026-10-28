# PROTOTYPE - throwaway. Question: how should an Unavailability reason appear in Issue/Fix output?
# Run: pwsh -File .\Tests\PROTOTYPE-availability-output.ps1   (works on 5.1 too)
# Scenarios are fake CA objects; nothing touches a real CA.

$RiskLabel = 'Unknown'   # today's placeholder rows get Medium (base score 3), except ESC16

$Hint = @{
    DnsFailed     = { param($c) "Check the dNSHostName on the CA's pKIEnrollmentService object and the DNS records for $($c.Fqdn)." }
    TransportDown = { param($c) "Check that $($c.Fqdn) is online and that a firewall allows TCP 135 and the dynamic RPC range 49152-65535 from this machine." }
    ServiceDown   = { param($c) "Check that the 'certsvc' service is running on $($c.Fqdn)." }
    AccessDenied  = { param($c) "Run Locksmith as a CA Administrator, or supply -Credential." }
}
$Sentence = @{
    DnsFailed     = { param($c) "Cannot resolve the CA host name $($c.Fqdn) in DNS." }
    TransportDown = { param($c) "Cannot connect to $($c.Fqdn) on TCP 135 (RPC endpoint mapper)." }
    ServiceDown   = { param($c) "$($c.Fqdn) is reachable, but the CA service did not answer (RPC server unavailable, 0x800706ba)." }
    AccessDenied  = { param($c) "$($c.Fqdn) answered, but denied access (0x80070005). This account cannot read the CA's configuration." }
}

$Scenarios = @(
    [pscustomobject]@{ Name = 'CA-DOWN';   Fqdn = 'ca1.corp.example'; Reachable = $false; Reason = 'ServiceDown';   Stages = 'DNS ok, ICMP failed, TCP 135 ok, certutil 0x800706ba'; ReadFailure = @{} }
    [pscustomobject]@{ Name = 'CA-DENIED'; Fqdn = 'ca2.corp.example'; Reachable = $false; Reason = 'AccessDenied';  Stages = 'DNS ok, ICMP ok, TCP 135 ok, certutil 0x80070005';     ReadFailure = @{} }
    [pscustomobject]@{ Name = 'CA-NODNS';  Fqdn = 'ca3.corp.example'; Reachable = $false; Reason = 'DnsFailed';     Stages = 'DNS failed, ICMP failed, TCP 135 failed, certutil 0x80070035'; ReadFailure = @{} }
    [pscustomobject]@{ Name = 'CA-PARTIAL'; Fqdn = 'ca4.corp.example'; Reachable = $true; Reason = $null;         Stages = 'DNS ok, ICMP ok, TCP 135 ok, certutil ok';             ReadFailure = @{ CAAdministrator = 'Access denied (0x80070005)' } }
)

# Variant A: one row per technique, same Technique values as today.
function New-VariantA($ca) {
    if (-not $ca.Reachable) {
        foreach ($t in 'DETECT', 'ESC6', 'ESC11', 'ESC16') {
            [pscustomobject]@{ Technique = $t; Name = $ca.Name; RiskName = $RiskLabel
                Issue  = "$(& $Sentence[$ca.Reason] $ca) Not evaluated. Stages: $($ca.Stages)."
                Fix    = & $Hint[$ca.Reason] $ca
                Revert = 'N/A' }
        }
    } elseif ($ca.ReadFailure.Count) {
        foreach ($k in $ca.ReadFailure.Keys) {
            [pscustomobject]@{ Technique = 'ESC7'; Name = $ca.Name; RiskName = $RiskLabel
                Issue  = "Could not read $k on $($ca.Fqdn): $($ca.ReadFailure[$k]). ESC7 not evaluated."
                Fix    = & $Hint['AccessDenied'] $ca
                Revert = 'N/A' }
        }
    }
}

# Variant B: one consolidated row per CA with a new Technique value, and the per-technique rows go away.
function New-VariantB($ca) {
    if (-not $ca.Reachable) {
        [pscustomobject]@{ Technique = 'AVAILABILITY'; Name = $ca.Name; RiskName = $RiskLabel
            Issue  = "$(& $Sentence[$ca.Reason] $ca) Not evaluated: DETECT, ESC6, ESC7, ESC11, ESC16. Stages: $($ca.Stages)."
            Fix    = & $Hint[$ca.Reason] $ca
            Revert = 'N/A' }
    } elseif ($ca.ReadFailure.Count) {
        [pscustomobject]@{ Technique = 'AVAILABILITY'; Name = $ca.Name; RiskName = $RiskLabel
            Issue  = "Partly evaluated. Could not read: $($ca.ReadFailure.Keys -join ', ') ($($ca.ReadFailure.Values -join '; ')). ESC7 not evaluated."
            Fix    = & $Hint['AccessDenied'] $ca
            Revert = 'N/A' }
    }
}

foreach ($variant in 'A', 'B') {
    $rows = foreach ($ca in $Scenarios) { & "New-Variant$variant" $ca }
    ''; "######## VARIANT $variant  ($(@($rows).Count) rows for 4 CAs) ########"
    '--- Mode 0 (Format-Table) ---'
    $rows | Format-Table Technique, @{l = 'CA Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Issue -Wrap | Out-String -Width 130
    '--- Mode 1 (Format-List), first row ---'
    $rows | Select-Object -First 1 | Format-List Technique, @{l = 'CA Name'; e = { $_.Name } }, @{l = 'Risk'; e = { $_.RiskName } }, Issue, Fix | Out-String -Width 130
}
