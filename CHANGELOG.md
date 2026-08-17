# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Optional HTML summary output for client-facing delivery.
- Optional read of legacy per-user MFA state behind an explicit opt-in switch, so the least-privilege default is preserved.
- Pester tests covering `Get-RiskAssessment` and AMP scope resolution against mocked Graph payloads.

## [1.0.0] - 2026-08-17

Initial public release.

### Added
- `-ExportTickets`: PSA-importable ticket queue with generic column names mapped at import time. Critical findings get individual tickets always; High findings get individual tickets up to `-MaxIndividualTickets` then batch into a campaign ticket; Moderate becomes a single legacy per-user MFA investigation ticket. Each description is self-contained with numbered remediation steps, and every sequence registers the new method before removing the phone method.
- `-MaxIndividualTickets`: cap on per-user ticket generation, default 50. Exists because a tenant with `All users` targeting would otherwise produce a ticket per employee.
- `examples/Example-Tickets.csv`: sample ticket export from fictional data, for testing PSA import mapping.
- `-HtmlReport`: self-contained client-ready HTML report with deadline countdowns, risk-band cards, resolved policy scope, and a table limited to actionable findings. No external assets or JavaScript. All user-supplied strings HTML-encoded, because directory display names are attacker-influenceable and an unencoded one would execute in the reader's browser.
- `-CustomerName`: heading applied to the HTML report; auto-populated from the tenant list label during a sweep.
- `-ExportRemediationGroup`: writes the Critical/High/Moderate population as a separate UPN list, ready for bulk import into the migration security group. Read-only; the tool produces the list and does not create or populate anything.
- `examples/Example-Report.html`: rendered sample report built entirely from fictional data.
- `Invoke-EntraSmsVoiceSweep.ps1`: multi-tenant sweep runner. One CSV per tenant plus a cross-tenant triage summary sorted failures-first then by Critical count. A single tenant failing (missing consent, app registration not deployed) logs and continues rather than ending the sweep.
- App-only certificate authentication on the assessment script via a dedicated `AppOnly` parameter set. Client secrets are deliberately unsupported.
- Tenant-mismatch guard: when `-TenantId` is a GUID and the established Graph context does not match it, the run aborts instead of writing a mislabelled report.
- `examples/tenants.sample.csv` showing the `TenantId` / `CustomerName` input format.
- Read-only correlation of Entra Authentication Methods Policy scope for `sms` and `voice` with the Graph authentication-method registration report.
- Transitive group resolution for AMP include and exclude targets, so nested group membership is honoured.
- Five-band risk classification (Critical, High, Moderate, Low, Informational) with a plain-language reason per user.
- Registration campaign state reporting, which is the setting Microsoft sets to Microsoft managed for in-scope tenants on 2026-09-01.
- Retry with bounded exponential backoff on HTTP 429, 503, and 504, so throttling on large tenants produces a slow run rather than a silently truncated one.
- `InRegistrationReport` column and `UsersMissingFromReport` summary field, distinguishing "no methods registered" from "no row in the report."
- `OldestReportRowUtc` summary field, exposing the age of the underlying report data as a confidence marker.
- `-PassThru` switch for pipeline analysis without re-reading the CSV.
- `smsSignIn` added to the tracked phone-method set alongside `mobilePhone`, `alternateMobilePhone`, and `officePhone`.
- Full include/exclude target notes with transitive member counts in the console summary.
- Cached group display-name resolution for AMP include and exclude targets, so the summary reads `Group: Sales Team [guid] (412 transitive user members)` instead of a bare GUID. Requires no additional scope; `displayName` is a basic group property already covered by `GroupMember.Read.All`. Falls back to the GUID if the group is deleted or inaccessible rather than failing the run.
- Console timeline now prints 2027-01-28 (customer-managed telecom provider configuration deadline) and 2027-02-01 (retirement) as separate lines, because conflating them is a known source of confusion.
- Link to the Microsoft passkey deployment guide in the console output.
- `SECURITY.md`, `docs/Risk-Classification.md`, `docs/Microsoft-Migration-Background.md`, MIT `LICENSE`, PowerShell-oriented `.gitignore`, and a fictional sample CSV.

### Fixed
Corrections applied to the pre-release working script during review:

- `-OutputPath` default threw when `$PSScriptRoot` was empty (script pasted into a console or dot-sourced). Now falls back to the current directory.
- Result sort placed non-admins ahead of admins within a risk band because `IsAdmin` sorted ascending. Admins now sort first.
- Include-target note read `All enabled member users` while the code added guests as well. Corrected to `All enabled users (members and guests)`.
- Guest detection compared `userType` against lowercase `guest`; Graph returns `Guest`, so the guest branch never fired.
- Registration report page size reduced from 999 to 500, which some tenants reject on the reports endpoint.
- `Get-MgContext` scope comparison could throw under `Set-StrictMode -Version Latest` when the context carried no `Scopes` property.
- No guard existed for a tenant returning zero enabled users; that now fails fast with an actionable message instead of producing an empty report.
- Terminology corrected throughout from `SmsVoiceMethods` to `PhoneMethods`, because Entra stores a phone number with a type rather than separate SMS and voice registrations. The old naming implied a per-user split the data does not support.

### Security
- **CSV formula injection guard** on every export. A display name beginning with `=`, `+`, `-`, `@`, tab, or carriage return is prefixed with a single quote so Excel treats it as literal text. Without this, a crafted display name executes when the manager opens the report and can exfiltrate adjacent rows.
- **Output ACL hardening** on by default on Windows. Report files no longer inherit the parent directory ACL; access is restricted to the file owner and local Administrators. Opt out with `-SkipAclHardening`.
- **Content Security Policy and no-referrer** on the HTML report. No scripts, no external requests, no form actions, no base URI. Defence in depth behind the existing HTML encoding.
- **Path traversal guard** in the sweep runner. Customer labels from a tenant list CSV are sanitised of path characters, stripped of leading and trailing dots, and reduced to the leaf, so a crafted label cannot write outside `-ReportRoot`.
- **Single export choke point** (`Export-AssessmentCsv`) so injection protection and ACL hardening cannot be forgotten on a future export.
- **URI escaping** on the group identifier in the display-name lookup.
- All Graph calls are HTTP GET. No create, update, or delete operation exists in the script.
- Delegated scopes limited to `Policy.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`.
- Graph base URI declared once as `$script:GraphBase` so the network surface is auditable by reading the file.
- Default CSV output filename pattern, `*.tenant.csv`, and common report directories excluded in `.gitignore`.

[Unreleased]: https://github.com/<your-account>/entra-passkey-readiness/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/<your-account>/entra-passkey-readiness/releases/tag/v1.0.0
