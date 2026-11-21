# Spec: Tenant Profiles

Status: ready-for-agent

## Problem

Every run of `Get-EntraSmsVoiceMigrationImpact.ps1` needs `-TenantId`, `-ClientId`, `-CertificateThumbprint`, `-CustomerName`, `-ExcludeUpnPattern` and `-TicketHistoryPath` typed in again. The Sweep's `tenants.csv` only holds `TenantId` and `CustomerName`. Switching between Tenants should be one choice.

## Constraints

- No secrets in a profile: certificate thumbprints only, never keys or client secrets.
- Real profiles are never committed.
- Every Graph call stays read-only (GET).
- A client must be able to audit the scripts.

## Model

See `GLOSSARY.md` (Customer, Tenant, Tenant Profile, Sweep) and `docs/adr/0001-shared-tenant-profile-helper.md`.

- Each Tenant has exactly one Tenant Profile. A Customer with several Tenants has several profiles that share a `CustomerName`.
- Allowed keys: `SchemaVersion` (must be 1), `TenantId`, `CustomerName`, `ClientId`, `CertificateThumbprint`, `ExcludeUpnPattern` (array), `TicketHistoryPath` (optional; defaults to the Tenant's `reports/` folder). Report switches are not profile keys.

## File and storage

- Format: `.psd1`, read only with `Import-PowerShellDataFile`.
- File name: `<name>.profile.psd1`, where name matches `^[a-z0-9][a-z0-9-]{0,62}$` (case-insensitive). The name is the file name without the extension.
- Profile folder, first match wins: `-TenantProfileRoot`, then `$env:ENTRA_SMSVOICE_PROFILE_ROOT`, then `./profiles`.
- `.gitignore`: add `/profiles/` and `*.profile.psd1`, then allow `!examples/Example.profile.psd1`.
- The profile folder gets the same ACL/chmod hardening as reports. If it is readable by everyone, warn but don't stop. `-SkipAclHardening` turns this off.

## Validation (fail closed, terminating errors)

- Any key that isn't allowed is an error, so a stray `ClientSecret` stops the run.
- `CertificateThumbprint` must match `^[0-9A-Fa-f]{40}$`.
- A missing or unknown `SchemaVersion` is refused.
- `TenantId` must be a GUID or a verified domain, checked with `Resolve-TenantIdentifier`, which moves into the shared helper.
- Error messages name the file and the key, never the value.

## Selecting and precedence

- `-TenantProfile <name>` (with an ArgumentCompleter) or `-TenantProfilePath <file>`. The two are mutually exclusive parameter sets. (`-Profile` is avoided because it collides with `$PROFILE`.)
- On a single-tenant run, an explicit parameter beats the profile value, and a `Write-Verbose` line names each overridden key.
- In a Sweep, the profile value beats the Sweep-wide parameter. Sweep-wide parameters only fill in keys a profile leaves blank.

## Per script

- **Assessment** (`Get-EntraSmsVoiceMigrationImpact.ps1`): profile parameter sets. Logs the profile name.
- **Sweep** (`Invoke-EntraSmsVoiceSweep.ps1`): `-TenantProfile <name[]>` and `-AllTenantProfiles`, alongside the existing `-TenantListPath`, which stays unchanged. If two profiles have the same `TenantId`, the whole Sweep is refused before any connection, and the error names both files. The summary gets a `TenantProfile` column (the name only).
- **GUI** (`Show-EntraSmsVoiceSweepGui.ps1`): when profiles exist, show a checklist of them displaying `CustomerName` and `TenantId` only, never the thumbprint. The CSV picker stays as a fallback.
- **Compare** (`Compare-EntraSmsVoiceAssessment.ps1`): `-TenantProfile` resolves the Tenant's report folder (named the same way the assessment names it) and compares the two newest exports. It errors when fewer than two exist. It is mutually exclusive with `-BaselinePath`/`-CurrentPath`.

## Code layout

`EntraSmsVoice.TenantProfile.ps1` at the repo root, dot-sourced by all four scripts. A script fails immediately with a clear message when the file is missing (ADR 0001).

## Done when

- Pester tests for the helper cover: the key allow-list, a bad thumbprint, an unknown SchemaVersion, a bad name, folder resolution order, single-run versus Sweep precedence, and duplicate TenantId.
- A RepoHygiene test fails if any `*.profile.psd1` other than the example is tracked.
- `examples/Example.profile.psd1` exists, with a comment on every key.
- README and `docs/Operations-Playbook.md` have sections on this, and `CHANGELOG.md` has an `[Unreleased]` entry.
- Pester and PSScriptAnalyzer pass, and no write calls to Graph were added.

## Out of scope

- A `New-…Profile` helper script.
- Removing the GUI's duplicate copy of tenant-identifier validation.
- Report switches in profiles.
