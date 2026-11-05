# Locksmith

Locksmith finds and fixes misconfigurations in Active Directory Certificate Services (AD CS).

## CA availability

**Availability check**:
The multi-stage probe Locksmith runs against a Certificate Authority before reading its configuration.
_Avoid_: Ping, online check, connectivity test

**Stage**:
One step of an Availability check (DNS, ICMP, transport, `certutil` ping). Every Stage runs and records its own result.
_Avoid_: Gate, step, test

**Reachable**:
True if and only if Locksmith can reach the CA's admin interface (the `certutil` ping succeeds). The other Stages only explain a false result, so a CA that answers but denies access is not Reachable.
_Avoid_: Verdict, online, offline, status

**Unavailability reason**:
The human-readable cause of a CA that is not Reachable or of a failed read, built from the Stage results and the parsed `certutil` error.
_Avoid_: Error, failure message
