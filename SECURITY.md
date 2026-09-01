# Security Policy

## Supported versions

Security fixes are prioritized for the latest published Locksmith release and
the current `main` branch. If you are using an older release, upgrade to the
latest release before reporting unless the issue is specific to the upgrade
path.

## Reporting a vulnerability

Do not report security vulnerabilities in public GitHub issues, discussions, or
pull requests.

Email vulnerability reports to <security@dotdot.horse>. Include as much of the
following information as you can safely share:

- The Locksmith version or commit SHA.
- The affected command, mode, scan, or remediation path.
- The Windows and PowerShell versions used.
- A clear description of the security impact.
- Minimal reproduction steps, sample output, or logs with secrets and sensitive
  environment details removed.
- Whether the issue is already being exploited or publicly discussed.

The maintainers will review the report, coordinate follow-up privately, and
publish public details after a fix or mitigation is available when disclosure is
appropriate.

## Handling sensitive AD CS data

Locksmith output can include names, distinguished names, SIDs, certificate
authority details, and remediation commands from an Active Directory
environment. Remove organization-specific or sensitive values before sharing
logs, screenshots, generated scripts, CSV files, or command output publicly.
