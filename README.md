# entra-passkey-readiness

[![CI](https://github.com/Blackvectra/entra-passkey-readiness/actions/workflows/ci.yml/badge.svg)](https://github.com/Blackvectra/entra-passkey-readiness/actions/workflows/ci.yml)
[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7.0%2B-5391FE)](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
[![Read-only](https://img.shields.io/badge/Graph%20calls-GET%20only-0F9D6E)](#security)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Read-only PowerShell assessment that identifies which Microsoft Entra ID users are exposed to the retirement of Microsoft-provided SMS and voice authentication, and which are ready for passkeys.

It answers a question the Entra portal does not answer directly: **which specific users are both targeted by the SMS/voice Authentication Methods Policy and unable to satisfy MFA without it after the retirement date.**

Every Microsoft Graph call is a GET. It does not modify users, groups, policies, authentication methods, or registration campaigns, which is what makes it safe to run against a customer tenant during business hours without a change window.

## Quick start

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

.\Get-EntraSmsVoiceMigrationImpact.ps1
```

That is the whole thing. A browser opens, you sign in as Global Reader or Security Reader, and you get two spreadsheets beside each other:

| File | What it is |
|---|---|
| `...Impact.csv` | The full assessment: one risk-ranked row per exposed user, highest risk first |
| `..._ActionList.csv` | The work list: affected users only, what they have, what to do. Attach it to a ticket ([sample](examples/Example-ActionList.csv)) |

Both open straight into Excel. Values that would otherwise be read as formulas are neutralised on the way out, so a display name beginning `=` cannot execute when somebody opens the file.

Add `-CustomerName "Contoso Manufacturing"` to put the client's name into every filename, which is what you want when you are running several clients and then attaching one set to that client's ticket:

```
EntraSmsVoiceMigrationImpact_Contoso-Manufacturing_20260817_170000.csv
EntraSmsVoiceMigrationImpact_Contoso-Manufacturing_20260817_170000_ActionList.csv
```

That is the only switch most runs need. Use `-OutputPath` if you want them somewhere specific; everything else is named from it.

Two optional extras: `-HtmlReport` adds a self-contained HTML report to hand a client directly ([sample](examples/Example-Report.html)), and `-ExportTickets` adds a CSV shaped for bulk PSA import ([sample](examples/Example-Tickets.csv)). Neither is needed for the normal run, and nothing is created in any external system by any of it — every output is a file on disk.

### Signing in

For a single customer, **omit `-TenantId` and just sign in.** The run reports whichever tenant you authenticated to, so it cannot be wrong about which customer it assessed.

`-TenantId` exists for the case where a leftover Graph session from a previous customer would otherwise be reused silently — so pass it whenever you work across several tenants in one sitting. It takes a **tenant GUID or a verified domain**, not the account you sign in with:

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.org                # verified domain
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com    # or the initial domain
```

Passing a sign-in name — `-TenantId administrator@contoso.org` — is the obvious thing to try and the parameter takes it: the domain is used as the tenant and the run says so. Anything that is neither a GUID nor a domain is rejected before the sign-in prompt rather than after it.

**Passwords are not a parameter, and will not be.** Interactive sign-in for one-off runs; certificate-based app-only for anything scheduled or estate-wide ([below](#unattended-authentication)). Both work with MFA and Conditional Access, which a password in a script does not.

## The three scripts

| Script | Use it to |
|---|---|
| `Get-EntraSmsVoiceMigrationImpact.ps1` | Assess one tenant. This is the core of the project. |
| `Invoke-EntraSmsVoiceSweep.ps1` | Assess many tenants, with optional concurrency and resume. |
| `Compare-EntraSmsVoiceAssessment.ps1` | Diff two assessments to see whether the campaign is moving anybody. Reads files only; no Graph, no permissions. |

## Contents

- [Why this exists](#why-this-exists) — the timeline, and the two populations people conflate
- [Prerequisites](#prerequisites) — modules, roles, Graph scopes
- [Usage](#usage) — single tenant, estate sweeps, progress tracking, reports, tickets
- [Output](#output) — console summary and CSV schema
- [Service accounts](#service-accounts-and-shared-mailboxes) — keeping non-human accounts out of the work queue
- [Legacy per-user MFA](#legacy-per-user-mfa) — the one exposure that needs a beta endpoint
- [Fixing what it finds](#fixing-what-it-finds) — a reviewed script, never an automatic write
- [Who actually gets stopped](#who-actually-gets-stopped) — the lockout population, which is not the same as the risk bands
- [Risk classifications](#risk-classifications) — the five bands
- [Coverage](#coverage-who-this-actually-finds) — exactly who this finds, and who it does not
- [Limitations](#limitations) — read before presenting results to a client
- [Is MFA even enforced?](docs/MFA-Enforcement.md) — why a Conditional Access policy is not the same as MFA being enforced
- [Troubleshooting](#troubleshooting)
- [Development](#development) — tests, linting, contributing
- [Security](#security)

Running this across an estate? Start with the [Operations Playbook](docs/Operations-Playbook.md): where the time actually goes, what to automate first, and the recurring loop.

---

## Why this exists

Microsoft announced on July 13, 2026 that Microsoft-provided SMS and voice authentication in Entra ID is being retired, with passkeys becoming the default authentication experience.

| Date | What happens |
|---|---|
| 2026-09-01 | Users enabled for SMS or voice in the Authentication Methods Policy (AMP) or legacy per-user MFA are auto-enabled for passkeys. The registration campaign is set to Microsoft managed and users are nudged to register. |
| 2026-09-18 | Customer-managed telecom provider options, terms, and pricing published through the Microsoft Security Store. |
| 2026-10-30 | Customer-managed telecom providers can be configured through the Microsoft Security Store. |
| 2027-02-01 | Microsoft-provided SMS and voice delivery is retired. No opt-out. Users whose only MFA method is a phone number are blocked and forced to register a phishing-resistant method. |

A temporary opt-out exists for the 2026-09-01 through 2027-02-01 changes. There is no opt-out for the 2027-02-01 enforcement.

Two distinct populations matter, and conflating them is the most common planning error:

1. **Policy scope** — users targeted by the SMS or voice method in AMP. This set drives the September 1 auto-enablement and nudge, and it is usually the larger set.
2. **Method registration** — users who actually have a phone number registered as an authentication method. This set drives who gets blocked on February 1.

This tool reports both, per user, in one pass, and classifies the intersection.

### Relationship to Microsoft's analyzer

Microsoft publishes [entra-sms-voice-usage-analyzer](https://github.com/microsoft/entra-sms-voice-usage-analyzer). The two tools answer different questions and are complementary.

| | Microsoft's analyzer | This tool |
|---|---|---|
| Graph scopes | `Policy.Read.All`, `Group.Read.All` | `Policy.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All` |
| Modules required | 3 | 1 |
| Resolves group targets to users | No | Yes, transitively |
| Reads registration report | No | Yes |
| Output | Policy include/exclude targets | One risk-ranked row per exposed user |
| Answers "is my tenant in scope?" | Yes | Yes |
| Answers "which users get blocked?" | No | Yes |

Run Microsoft's script for the authoritative tenant-level policy and campaign view. Run this one to build the remediation work queue.

**Date discrepancy worth knowing.** Microsoft's script prints `Jan 28, 2027` as the retirement date in its impact summary. Microsoft Learn does not use that date anywhere. What Learn states is:

- **2027-02-01** is the retirement, and the date by which a customer-managed telecom provider must be configured to keep using SMS or voice.
- **2026-10-30** is when configuring a provider through the Security Store first becomes possible.

Treat `Jan 28, 2027` as an artefact of Microsoft's analyzer rather than a published milestone, and work to February 1. Expect a client who has run both tools to ask.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| PowerShell | 7.0 or later (enforced by `#Requires`) |
| Module | `Microsoft.Graph.Authentication` (this is the only dependency) |
| Entra role | Global Reader or Security Reader |
| Network | Access to `graph.microsoft.com` |

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Delegated Graph permissions

All four scopes are read-only. The script requests them at connect time and will not proceed without them.

| Scope | Used for |
|---|---|
| `Policy.Read.All` | Authentication Methods Policy, SMS and voice method configuration, registration campaign state |
| `AuditLog.Read.All` | `reports/authenticationMethods/userRegistrationDetails` |
| `User.Read.All` | User objects, `accountEnabled`, `userType` |
| `GroupMember.Read.All` | Transitive group membership for AMP include/exclude targets |

If your tenant requires admin consent for delegated Graph scopes, have a Global Administrator or Privileged Role Administrator consent to these four before first run.

---

## Installation

```powershell
git clone https://github.com/<your-account>/entra-passkey-readiness.git
cd entra-passkey-readiness

# Only needed if downloaded as a zip rather than cloned
Get-ChildItem *.ps1 | Unblock-File
```

---

## Usage

```powershell
# Standard run against a named tenant
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com

# Full inventory including users with no exposure, to a specific path
.\Get-EntraSmsVoiceMigrationImpact.ps1 -IncludeUnaffected -OutputPath C:\Reports\Contoso-Entra-Migration.csv

# Verbose run with objects returned to the pipeline for further analysis
$rows = .\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com -PassThru -Verbose
$rows | Where-Object Risk -eq 'Critical' | Format-Table DisplayName, UserPrincipalName, PhoneMethodsRegistered
```

**Always pass `-TenantId` when working across multiple tenants.** It is what prevents the script from silently reusing a Graph session left over from a previous tenant and reporting the wrong customer's data.

### Multi-tenant sweep (MSP scale)

`Invoke-EntraSmsVoiceSweep.ps1` runs the assessment across many tenants, writes one CSV per tenant, and produces a cross-tenant triage summary. A single tenant failing does not end the sweep.

```powershell
# Interactive, a handful of tenants (one sign-in prompt per tenant)
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantId contoso.onmicrosoft.com, fabrikam.onmicrosoft.com `
    -ReportRoot D:\ClientEvidence\EntraMigration

# Unattended across the full estate
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
    -ReportRoot D:\ClientEvidence\EntraMigration `
    -ClientId 11111111-1111-1111-1111-111111111111 `
    -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
```

The tenant list is a CSV with a `TenantId` column and an optional `CustomerName` column used to name the output folder. See [examples/tenants.sample.csv](examples/tenants.sample.csv).

Results sort failures first, then by Critical count descending, so the estate triage order is the read order.

**Point `-ReportRoot` at your protected client documentation store, never at a git working directory.**

#### Running tenants concurrently

`-ThrottleLimit` assesses up to 16 tenants at once. On a large estate this is the difference between a sweep you start and watch and a sweep you start and come back to.

```powershell
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
    -ReportRoot D:\ClientEvidence\EntraMigration `
    -ClientId 11111111-1111-1111-1111-111111111111 `
    -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
    -ThrottleLimit 6
```

Each concurrent tenant runs in **its own pwsh process**, not a runspace. `Microsoft.Graph.Authentication` holds the signed-in context in process-wide state, so concurrent connections inside one process can serve one customer's token to another customer's report. That is the exact failure this project exists to prevent, so the isolation boundary is a process.

Two consequences worth knowing:

- **App-only authentication is required.** Interactive sign-in cannot be driven concurrently, and the script refuses rather than half-working.
- **Graph throttling is per-tenant**, so concurrency across different tenants does not compound it. Concurrency will not make a single large tenant faster.

#### Resuming an interrupted sweep

A ninety-tenant sweep that dies at tenant sixty should not restart at tenant one.

```powershell
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
    -ReportRoot D:\ClientEvidence\EntraMigration `
    -ClientId 11111111-1111-1111-1111-111111111111 `
    -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
    -ThrottleLimit 6 -Resume
```

`-Resume` reads the most recent `SweepSummary_*.csv` under `-ReportRoot` and skips every tenant already recorded as `Success`. Skipped tenants are **carried into the new summary** rather than dropped, so the summary still describes the whole tenant list and a second resume does not redo the first run's work.

Matching is on the customer label rather than the tenant ID, because a successful row records the tenant GUID Graph reported, which will not equal the verified domain you supplied.

### Tracking progress between runs

The first assessment answers "who is exposed." Every run after it answers "did the campaign move anybody," and that question is unreadable from a 400-row CSV where 380 rows are identical to last month's.

```powershell
.\Compare-EntraSmsVoiceAssessment.ps1 `
    -BaselinePath .\Contoso-2026-09.csv `
    -CurrentPath  .\Contoso-2026-10.csv
```

Every user is classified by direction of travel, and the report sorts regressions first, because a user who went backwards is the only category that means something is actively wrong.

| Movement | Meaning |
|---|---|
| `Regressed` | Risk band worsened. Lost a passwordless method, or newly resolved into policy scope. |
| `New` | Appeared in this run. New account, newly in scope, or newly present in the registration report. |
| `Improved` | Risk band improved. Usually the remediation completing. |
| `Resolved` | No longer a migration candidate at all. Also what a disabled or deleted account looks like, so it is reported rather than assumed to be good news. |
| `Unchanged` | No movement. Excluded unless you pass `-IncludeUnchanged`. |

The console summary reports `LeftActionableBands` and `EnteredActionableBands`. The first is the number worth putting in a client status update; the second is usually new starters or a group membership change.

Users are matched on object ID, so a rename does not read as a new account. Where only the UPN matched, the row records `MatchedOn = UserPrincipalName` so you can tell the difference.

This script touches no tenant and needs no Graph permissions or connectivity. It compares two files.

```powershell
# Who went backwards since the last run, worst first
$changes = .\Compare-EntraSmsVoiceAssessment.ps1 -BaselinePath .\a.csv -CurrentPath .\b.csv -PassThru
$changes | Where-Object Movement -eq 'Regressed' | Format-Table DisplayName, BaselineRisk, CurrentRisk, Note
```

### Unattended authentication

App-only runs need the same four Graph permissions granted as **application** permissions with admin consent in each tenant, and a certificate registered on the app registration.

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 `
    -TenantId 00000000-0000-0000-0000-000000000000 `
    -ClientId 11111111-1111-1111-1111-111111111111 `
    -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
    -OutputPath D:\ClientEvidence\contoso.csv
```

Client secrets are deliberately not supported. A secret that can read identity posture across an entire customer estate should not exist as a script parameter.

When `-TenantId` is supplied as a GUID, the script verifies the established Graph context matches it and aborts rather than writing a mislabelled report.

### Client-ready HTML report

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
    -CustomerName "Contoso Manufacturing"
```

`-HtmlReport` writes a self-contained HTML file beside the CSVs. Skip it unless you want something to hand a client directly; the spreadsheets carry the same findings. No CDN, no external assets, no JavaScript, so it survives being emailed, archived, or opened offline years later.

It is designed as a document rather than a dashboard, because it gets printed:

- **An executive summary in prose**, generated from the same numbers as the cards. A report that shows only counts leaves the reader to do the interpretation, and the interpretation is what they are paying for. It refuses to describe a zero-candidate tenant as finished unless the legacy per-user MFA state was actually read.
- **Findings split into one table per band.** A technician works Critical to completion before touching High, and the band boundary is where that decision gets made.
- **A next step under every row.** The diagnosis and the action sit together, so the report can be worked from directly rather than being a list you then have to interpret.
- **A countdown to both deadlines**, computed when the report is generated.
- **The resolved policy scope with group names**, so the targeting is auditable rather than a list of GUIDs.
- **A scope-and-method section** stating what was and was not assessed, so the deliverable stands up in a client conversation without this README open beside it.
- Only Critical, High, and Moderate findings are tabled, so the accounts that matter are not buried under the ones that do not.

Printing to PDF produces a clean document: column headers repeat across pages, bands and cards do not straddle page breaks, and page margins are set.

All user-supplied strings are HTML-encoded before rendering. Directory display names are attacker-influenceable in tenants that permit self-service profile edits or B2B invites, and an unencoded display name containing markup would execute in the browser of whoever you emailed the report to.

See [examples/Example-Report.html](examples/Example-Report.html) for a rendered sample built entirely from fictional data.

### The action list

The action list is written on every run. It contains just the Critical, High, and Moderate users, and does two jobs:

- **The file you attach to a ticket you raised yourself.** Eight columns, sorted worst-first with admins ahead of standard users, so it is worked top-down: `Risk`, `DisplayName`, `UserPrincipalName`, `IsAdmin`, `PhoneMethodsRegistered`, `IsPasswordlessCapable`, `NextStep`, `UserId`. Everything a technician needs and none of the diagnostic columns that make the full export wide.
- **The membership list** for the migration security group Microsoft's guidance tells you to create as step one, ready for bulk import on `UserPrincipalName`.

See [examples/Example-ActionList.csv](examples/Example-ActionList.csv).

Producing the list is read-only. Creating and populating the group stays a deliberate manual action, because that is a write and this tool does not write.

**If you raise tickets yourself, this is the file you want, and you can skip `-ExportTickets` entirely.** Nothing is created in any external system by either switch — every output is a file on disk.

### Ticket queue for your PSA

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
    -CustomerName "Contoso Manufacturing" -ExportTickets
```

`-ExportTickets` writes a flat CSV shaped for PSA import. Columns: `Priority`, `Summary`, `Company`, `ContactName`, `ContactEmail`, `UserId`, `Risk`, `Category`, `DueDate`, `Status`, `Source`, `Description`. Generic on purpose, since ConnectWise, Autotask, Halo, and Freshservice each name these differently; map them at import rather than baking one vendor's schema into the tool.

Ticket volume is managed deliberately:

| Risk | Ticketing |
|---|---|
| Critical | One ticket per user, always. Privileged accounts are never batched. |
| High | One ticket per user until Critical plus High individual tickets together reach `-MaxIndividualTickets` (default 50), then a single campaign ticket for the remainder. |
| Moderate | One investigation ticket for the whole population. The finding is about tenant configuration, not any individual. |
| Low / Informational | No ticket. |

A tenant with `All users` targeting can produce hundreds of High findings. Ticketing each one creates a backlog nobody works, so the overflow becomes a campaign ticket that points at the remediation group CSV.

Each `Description` is self-contained: the user, their registered methods, why the ticket exists, a **Next step** line, and numbered remediation steps. A tech can work it without opening the report.

That `Next step` line is the same string as the `NextStep` CSV column and the next step shown under the user's row in the HTML report. All three come from one function, so a change to the guidance lands everywhere at once rather than leaving the ticket queue saying something the report does not.

Every remediation sequence registers the new method before removing the phone method, because doing it in the other order creates the lockout you are trying to prevent. That ordering is enforced by a test across every risk band, not just written down.

Due dates target 2026-09-01 while that date is still ahead, then fall back to 2027-02-01.

See [examples/Example-Tickets.csv](examples/Example-Tickets.csv) for a sample built from fictional data. Test your import mapping against it before running against a real tenant.

**Note on multiline descriptions.** Ticket bodies contain embedded newlines inside quoted CSV fields. This is valid RFC 4180 and handled by every PSA tested, but some older importers reject it. Check against the sample first.

### Re-running without duplicating tickets

A monthly re-run must not raise a second ticket for everyone who has not remediated yet. It does not: the run records which users it ticketed, and a later run only raises a ticket for a user who is **new**, or whose risk band **got worse**.

Somebody who was High last month and is High today is already in somebody's queue, so raising it again adds no information — just a ticket a technician has to close.

```
Ticket queue (3 tickets): D:\ClientEvidence\contoso_Tickets.csv
  14 user(s) already ticketed by an earlier run and not raised again. History: D:\ClientEvidence\contoso_TicketHistory.json
```

The history file holds object IDs and risk bands only — no names, no UPNs — so it can sit wherever is convenient without carrying identifying data.

**One thing to get right.** The history defaults to a file beside the ticket CSV. If you write to dated output folders — which the [playbook](docs/Operations-Playbook.md) recommends — each run lands somewhere new and finds no history, so every run looks like a first run. Point `-TicketHistoryPath` at a stable path per customer:

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
    -OutputPath "D:\ClientEvidence\Contoso\$(Get-Date -f yyyy-MM-dd)\contoso.csv" `
    -ExportTickets -TicketHistoryPath 'D:\ClientEvidence\Contoso\TicketHistory.json'
```

The sweep does this for you: history lives in the per-tenant folder rather than the dated run folder, so a repeat sweep across the estate is already deduplicated.

`-IgnoreTicketHistory` raises tickets for everyone regardless, for rebuilding a queue that was lost. `TicketsSuppressedAsAlreadyRaised` in the summary tells you how many were held back, so a near-empty queue reads as "already ticketed" rather than "assessment found nothing".

### Parameters

#### `Get-EntraSmsVoiceMigrationImpact.ps1`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-TenantId` | string | current Graph context | Tenant GUID or verified domain — **not** a sign-in name, though a UPN is accepted and its domain used. Omit it to sign in interactively. Forces re-auth if it does not match the live session. Mandatory for app-only. |
| `-ClientId` | guid | none | App registration ID for unattended app-only auth. Requires `-CertificateThumbprint`. |
| `-CertificateThumbprint` | string | none | Certificate thumbprint for app-only auth. |
| `-OutputPath` | string | timestamped CSV beside the script, with `-CustomerName` folded in | Destination CSV path. The report and action list are named from it. Parent directory is created if missing. |
| `-IncludeUnaffected` | switch | off | Include every enabled user, not just migration candidates. |
| `-ExportFixScript` | switch | off | Also writes a `..._Remediation.ps1` of commands for you to review and run yourself. The assessment still writes nothing to any tenant, and the generated file refuses to run until you read it. See [Fixing what it finds](#fixing-what-it-finds). |
| `-SkipLegacyPerUserMfa` | switch | off | **Skips** the legacy per-user MFA read, which every run otherwise performs. Only worth setting to avoid the beta endpoint entirely; it costs you the assessment's one real blind spot. See [Legacy per-user MFA](#legacy-per-user-mfa). |
| `-ExcludeUpnPattern` | string[] | none | Regex patterns matched against the UPN. Matching users are marked `Excluded` and left out of every count and work queue. See [Service accounts](#service-accounts-and-shared-mailboxes). |
| `-HtmlReport` | switch | off | Also write a self-contained HTML client report beside the CSVs. |
| `-CustomerName` | string | none | Heading used on the HTML report. |
| `-ExportTickets` | switch | off | Also write a PSA-importable ticket queue. |
| `-MaxIndividualTickets` | int | 50 | Cap on individual tickets before High findings batch into a campaign ticket. |
| `-TicketHistoryPath` | string | beside the ticket CSV | Users already ticketed, so a re-run does not raise duplicates. See [Re-running without duplicating tickets](#re-running-without-duplicating-tickets). |
| `-IgnoreTicketHistory` | switch | off | Ticket every actionable user regardless of previous runs. |
| `-SkipAclHardening` | switch | off | Skip restricting output file permissions. Use only where the filesystem rejects ACL changes. |
| `-PassThru` | switch | off | Emit per-user objects to the pipeline in addition to the summary. |

#### `Invoke-EntraSmsVoiceSweep.ps1`

Accepts and passes through `-IncludeUnaffected`, `-SkipLegacyPerUserMfa`, `-ExcludeUpnPattern`, `-HtmlReport`, `-ExportTickets`, `-MaxIndividualTickets`, and `-SkipAclHardening`. Its own parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-TenantId` | string[] | none | One or more tenants. Accepts pipeline input. Mutually exclusive with `-TenantListPath`. |
| `-TenantListPath` | string | none | CSV with a `TenantId` column and optional `CustomerName`. |
| `-ReportRoot` | string | **required** | Output root. One subfolder per tenant. Point at your protected client documentation store. |
| `-ClientId` / `-CertificateThumbprint` | string | none | App-only auth. Both or neither. |
| `-AssessmentScriptPath` | string | same directory | Path to the assessment script. |
| `-ThrottleLimit` | int | 1 | Tenants assessed concurrently, 1 to 16. Above 1 requires app-only auth. |
| `-Resume` | switch | off | Skip tenants already recorded as `Success` in the newest sweep summary under `-ReportRoot`. |

#### `Compare-EntraSmsVoiceAssessment.ps1`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-BaselinePath` | string | **required** | The earlier assessment CSV. |
| `-CurrentPath` | string | **required** | The later assessment CSV. |
| `-OutputPath` | string | timestamped CSV beside `-CurrentPath` | Destination for the change report. |
| `-IncludeUnchanged` | switch | off | Include users whose band did not move. |
| `-SkipAclHardening` | switch | off | Skip restricting output file permissions. |
| `-PassThru` | switch | off | Emit per-user change objects to the pipeline. |

---

## Output

### Console summary

| Field | Meaning |
|---|---|
| `TenantId` | Tenant the assessment actually ran against |
| `DirectoryUsersReturned` / `EnabledUsersAssessed` / `UsersSkippedNotEnabled` | The assessment's own arithmetic. The last two must sum to the first — that is what makes a silently dropped user visible instead of invisible. |
| `RegistrationCampaignState` | `enabled`, `disabled`, or `default (Microsoft managed)` |
| `SmsPolicyState` / `VoicePolicyState` | AMP state of each method |
| `SmsPolicyInclude` / `SmsPolicyExclude` | Resolved include and exclude targets, with transitive member counts |
| `InSmsPolicyScope` / `InVoicePolicyScope` | Enabled users resolved into each method's scope |
| `UnresolvedPolicyTargets` | **Above zero means the two counts above are a floor, not a total.** The policy targets somebody this run could not resolve to users, so the tenant is at least as exposed as reported. Empty on a clean run. |
| `LegacyPerUserMfaChecked` | True unless `-SkipLegacyPerUserMfa` was set. False means that exposure is unassessed, whatever else the report says. |
| `LegacyPerUserMfaInForce` | Users `enabled` or `enforced` in legacy per-user MFA. In scope for the retirement whatever the modern policy says. |
| `LegacyPerUserMfaUnreadable` | Users whose state Graph would not return. Marked `(unreadable)`, never assumed clean. |
| `MigrationCandidates` | Users in policy scope **or** with a phone method registered |
| `Critical` / `High` / `Moderate` / `Low` | Risk-band counts across migration candidates |
| `PasswordlessCapableInScope` | In-scope users who already have a surviving method |
| `BlockedAtRetirement` | **Users stopped at sign-in on 2027-02-01.** A phone is their only method that satisfies MFA. The number to drive to zero. |
| `BlockedAdminsAtRetirement` | How many of those hold a privileged role |
| `UnrecognisedMethods` | Any registered method name this tool does not classify. Treated as not surviving, so affected users read as more exposed. |
| `StaleAccountsInActionList` / `NeverSignedInInActionList` | How much of the work queue is probably not a person. Check these against your leaver process before anybody starts chasing names. |
| `UsersMissingFromReport` | Enabled users with no row in the registration report (see Limitations) |
| `OldestReportRowUtc` | Age of the oldest registration-report row; the honest confidence marker for the run |

### CSV fields

| Column | Type | Description |
|---|---|---|
| `Risk` | string | Critical, High, Moderate, Low, or Informational. See [docs/Risk-Classification.md](docs/Risk-Classification.md). |
| `Reason` | string | Plain-language justification for the risk band. |
| `NextStep` | string | What to do about this user, specific to what they have registered. Same wording as the HTML report and the ticket queue, so the three cannot disagree. Every sequence registers the surviving method before removing the phone method. |
| `BlockedAtRetirement` | bool | **The lockout flag.** A phone method is registered and nothing else the user holds both survives the retirement and satisfies MFA. These are the accounts stopped at sign-in on 2027-02-01. See [Who actually gets stopped](#who-actually-gets-stopped). |
| `DisplayName` | string | Directory display name. |
| `UserPrincipalName` | string | UPN. |
| `UserType` | string | `Member` or `Guest`. |
| `IsAdmin` | bool | Reported by the registration report as holding a privileged role. |
| `InSmsPolicyScope` | bool | Resolved into the SMS method's AMP scope after exclusions. |
| `InVoicePolicyScope` | bool | Resolved into the voice method's AMP scope after exclusions. |
| `DaysSinceLastSignIn` | int or marker | Whole days since the last successful sign-in. `(none recorded)` means never, or not since April 2020 -- Microsoft keeps no history before then. `(not available)` means the tenant is not licensed to report sign-in activity (Entra ID P1/P2). **A name on a work queue that has not signed in for a year is a deprovisioning ticket, not a passkey one.** |
| `PerUserMfaState` | string | `disabled`, `enabled`, or `enforced` from legacy per-user MFA; `(not checked)` if `-SkipLegacyPerUserMfa` was set; `(unreadable)` if Graph would not answer. Always written, so the column never appears and disappears between runs. |
| `PhoneMethodsRegistered` | string | Semicolon-delimited subset: `mobilePhone`, `alternateMobilePhone`, `officePhone`, `smsSignIn`. |
| `AllMethodsRegistered` | string | Every method reported for the user, or `(no row in registration report)` when the report had no data for them. |
| `IsPasswordlessCapable` | bool | Reports a passwordless method. This is the mitigating control. |
| `UserId` | guid | Object ID. Kept last because it is a join key, not something you read. |

Sixteen columns, sorted highest risk first, then admins ahead of standard users, then display name.

The registration report also returns `isMfaCapable`, `isMfaRegistered`, `systemPreferredAuthenticationMethods`, and a per-row timestamp. None of them changed what anybody did with the file, so they are not written. Evidence age is still reported once, as `OldestReportRowUtc` in the summary, and a user with no report row is called out in `AllMethodsRegistered` rather than needing a column of its own.

---

## Service accounts and shared mailboxes

A tenant targeting `All users` surfaces every shared mailbox, sync account, and service account as a migration candidate. They are technically in scope, nobody signs into them interactively, and ticketing them wastes a technician's afternoon.

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
    -ExcludeUpnPattern '^svc-', '^shared-', '^noreply@'
```

Patterns are regular expressions matched case-insensitively against the UPN. Anchor them yourself: `^svc-` catches `svc-backup@contoso.com` and leaves `marc.svc-jones@contoso.com` alone, while `svc-` catches both. An invalid pattern fails at parameter binding, before the tenant is contacted.

**Matching users are marked, not deleted.** Their row stays in the assessment CSV with `Risk = Excluded`, and they are left out of every count, the action list, the tickets, and the report. That distinction matters: a filter that silently removes people from a security assessment is how a real account disappears behind a careless pattern, and nothing about the output would look unusual. The summary reports `UsersExcludedByPattern` and the patterns used, and the console says how many were removed.

Check that number on the first run for a new customer. If it is larger than the count of non-human accounts you expect, the pattern is too broad.

The sweep accepts the same parameter, since one naming convention usually covers a whole estate.

---

## Legacy per-user MFA

The one exposure this assessment can otherwise miss entirely.

Legacy per-user MFA is a separate enforcement layer that predates the Authentication Methods Policy and is not replaced by it. A user `enabled` or `enforced` there is in scope for the SMS and voice retirement whatever the modern policy says — and the modern registration campaign does not reach them, so a passkey push aimed at that user lands nowhere and the run after this one reports them unchanged.

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com
```

Without the switch, those users surface as `Moderate` with an instruction to go and check a portal by hand. Across an estate that is one manual check per tenant that does not happen, and a tenant still running on legacy per-user MFA assesses as unremarkable.

**It needs no extra access.** The state is readable at `GET /beta/users/{id}/authentication/requirements` with `Policy.Read.All` — which every run already requests — and Global Reader is a supported role. The switch is off by default because the endpoint is beta, not because it costs you permission. The cost is one batched Graph call per twenty users.

What changes when it is on:

| | Without the switch | With it |
|---|---|---|
| `PerUserMfaState` | `(not checked)` on every row | `disabled`, `enabled`, `enforced`, or `(unreadable)` |
| A user held in legacy MFA | `Moderate`, "go and check a portal" | The band their real exposure earns, up to `Critical`, with a next step that starts by converting them to the modern policy |
| A `Moderate` user who is genuinely clear | Indistinguishable from the above | Confirmed stale registration, no portal visit |
| Summary | — | `LegacyPerUserMfaChecked`, `LegacyPerUserMfaInForce`, `LegacyPerUserMfaUnreadable` |

**Not knowing never looks like knowing.** A denied read, a request Graph left unanswered, and a `200` with no state in the body all land as `(unreadable)`, counted in `LegacyPerUserMfaUnreadable`. None of them is ever treated as "no legacy MFA", because that reading is indistinguishable from a genuine all-clear and it is exactly the one that leaves somebody locked out with a clean report on file. A throttled request inside a batch — which returns `200` at the envelope level, so nothing above would retry it — is retried across rounds before being given up on.

A non-zero `LegacyPerUserMfaInForce` is also an MFA enforcement finding in its own right: per-user MFA sitting underneath a Conditional Access policy has its own trusted-IP bypass and its own remembered-device setting, neither of which Conditional Access knows about. See [docs/MFA-Enforcement.md](docs/MFA-Enforcement.md).

## Fixing what it finds

The assessment writes nothing to any tenant, and that does not change. What `-ExportFixScript` adds is a **file**:

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.org -ExportFixScript
```

You get `..._Remediation.ps1` beside the CSVs: one commented block per actionable user, with the exact Graph calls. Nothing in it has run, and it opens with a `throw` so running it unread does nothing at all. Every command that would change the tenant is commented out.

**The central remediation cannot be automated, by anyone.** There is no Graph call that registers a passkey on somebody's behalf — registration requires the user present with their device. That is the point of a passkey. What the script automates is the supporting cast, and the order is the whole value:

1. **Issue a Temporary Access Pass.** This is what lets somebody register a passkey *without* the phone they are about to lose. Skip it and you strand exactly the people you were trying to help.
2. **The user registers.** A human step. The script says so and stops.
3. **Verify the new method exists.**
4. **Only then remove the phone method.** This line is commented out and it is last, because removing a phone before a replacement is confirmed working is precisely the lockout this whole tool exists to prevent.

The commands need `UserAuthenticationMethod.ReadWrite.All` and `Policy.ReadWrite.AuthenticationMethod` — write permissions, well beyond the read-only set the assessment ran with. That escalation is yours to make deliberately.

## Who actually gets stopped

If the question is "will any of my users turn up on a Monday and be unable to work", the risk bands are not the answer. `BlockedAtRetirement` is.

Microsoft's blocking prompt on 2027-02-01 applies to users whose **only available MFA method is SMS or voice**. That is narrower than the risk bands, which measure whether a user holds a *passwordless* method. Microsoft Authenticator push is not passwordless and is also not being retired, so somebody holding it is `High` and is not stopped.

The two populations cut across each other. From the sample data:

| User | Band | Registered | Stopped on 2027-02-01 |
|---|---|---|---|
| Marcus Whitfield | High | `mobilePhone` | **Yes** |
| Tobias Lindqvist | High | `softwareOneTimePasscode` | No |
| Rosalind Achebe | Moderate | `officePhone`, `email` | **Yes** |
| Emeka Osondu | Low | `mobilePhone`, `windowsHelloForBusiness` | No |

A `Moderate` user can be stopped while a `High` user is not. Sorting your work by risk band alone will leave people locked out, which is why `BlockedAtRetirement` leads the console summary, gets its own band at the top of the HTML report, and sorts first inside each band of the action list.

**Read the bands as "how much migration work", and this number as "who stops working".** Drive it to zero before the date; the bands tell you how much campaign effort stands between here and that.

Two honest caveats:

- `email` and `securityQuestion` satisfy self-service password reset, not MFA, so they do not count as surviving. A temporary access pass expires by design and does not count either.
- A method this tool does not recognise is treated as **not** surviving, so an unfamiliar name makes a user look more exposed rather than less. Any such names are listed in `UnrecognisedMethods` in the summary. Over-warning costs a review; under-warning costs somebody their morning.

## Risk classifications

Summarised here; full logic and remediation guidance in [docs/Risk-Classification.md](docs/Risk-Classification.md).

| Band | Condition |
|---|---|
| **Critical** | Privileged user, in policy scope, phone method registered, not passwordless-capable |
| **High** | In policy scope with a registered phone method and no passwordless method, or in policy scope and not passwordless-capable |
| **Moderate** | Phone method registered, no passwordless method, but outside resolved modern policy scope — usually legacy per-user MFA exposure |
| **Low** | Exposed to the change but already passwordless-capable |
| **Informational** | No resolved exposure |
| **Excluded** | Not a risk level. The user matched `-ExcludeUpnPattern` and was left out of every count. |

---

## Coverage: who this actually finds

The claim is "every user in the tenant who is exposed." Here is exactly what that means, so you can defend it in a client conversation.

**Included.** Every enabled user object returned by `/users`, members and guests, with full pagination. Every user resolved into SMS or voice policy scope, including through nested groups, with exclusions applied afterwards as an override. Every user with a phone-based method in the registration report, whether or not they resolve into modern policy scope.

**A user cannot be silently missed on the registration side.** If a user has no row in the registration report, the registration-derived fields default to `False`, which means `IsPasswordlessCapable` is `False`, which means an in-scope user lands in `High` rather than being quietly dropped. The failure mode is a false positive, not a false negative. Those rows read `(no row in registration report)` in `AllMethodsRegistered`, and `UsersMissingFromReport` counts them, so you can tell the difference between "nothing registered" and "no data".

**Pagination failures are not silent either.** A throttled request retries with backoff, and an unrecoverable one throws. There is no code path that returns a short list and reports it as complete.

**Not included, by design or by data source:**

| Population | Why | What to do |
|---|---|---|
| Disabled users | `userRegistrationDetails` does not return them | Re-run after any bulk re-enablement |
| Users enabled for SMS/voice only via legacy per-user MFA | Read on every run, from a beta endpoint | Covered by default. `-SkipLegacyPerUserMfa` turns it off, and then the `Moderate` band surfaces the symptom with nothing to confirm it. |
| Effective Conditional Access outcome | Not read | Policy scope is not the same as being challenged at sign-in |
| Non-human accounts | Shared mailboxes, sync accounts, and service accounts appear as ordinary users | Filter by your naming convention or exclude them from the remediation group after review |

That last one matters operationally. A tenant with `All users` targeting will surface shared mailbox and service account objects as migration candidates. They are technically in scope but nobody signs into them interactively, so review before they become tickets.

## Limitations

These are properties of the data sources, not defects. Read them before presenting results to a client.

- **Disabled users are excluded.** `userRegistrationDetails` does not return disabled users. The script reads `accountEnabled` separately and assesses enabled users only. Disabled accounts that get re-enabled after the assessment are not represented.
- **Reporting latency.** The registration report is not real-time. `OldestReportRowUtc` in the summary is the age of the oldest row behind the assessment, so the confidence in a run is visible. Do not treat a run as a live directory query.
- **SMS and voice are not separately registered.** Entra stores a phone number with a type, not an "SMS registration" and a "voice registration." `mobilePhone` can satisfy both; `officePhone` is voice-only. There is no clean per-user SMS-versus-voice split available, so the script reports phone-method capability and leaves policy scope to distinguish intent.
- **Legacy per-user MFA is read from a beta endpoint.** Users enabled for SMS or voice through legacy per-user MFA service settings are in scope for the retirement, and that state has no Graph v1.0 equivalent -- it exists only at `/beta/users/{id}/authentication/requirements`. Every run reads it, using the `Policy.Read.All` the script already requests. `-SkipLegacyPerUserMfa` opts out, and then `PerUserMfaState` reads `(not checked)` on every row and that exposure is unassessed.
- **Conditional Access is not evaluated.** A user may be in AMP scope but never actually challenged, or may be blocked by a Conditional Access grant this script does not read. Policy scope is not the same as effective sign-in behaviour. It is also not the same as MFA being enforced at all -- see [docs/MFA-Enforcement.md](docs/MFA-Enforcement.md) for the ten common reasons a tenant with a Require-MFA policy is not actually requiring MFA.
- **Guest and B2B readiness.** Guests are assessed, but passkey support for B2B and internal guest users is on a separate Microsoft timeline. Treat guest findings as requiring independent validation.
- **Nested groups are resolved transitively; dynamic groups are point-in-time.** A dynamic group's membership can change between the assessment and September 1.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Microsoft.Graph.Authentication is required but is not installed.` | Run `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`. |
| Sign-in succeeds but results are for the wrong tenant | A cached Graph session was reused. Run `Disconnect-MgGraph`, then re-run with an explicit `-TenantId`. |
| `Insufficient privileges to complete the operation` on the reports endpoint | `AuditLog.Read.All` was not consented. Have an admin consent to all four delegated scopes. |
| `No enabled users were returned` | The signed-in account lacks `User.Read.All`, or is signed in to a tenant with no enabled users. |
| Run is slow or intermittently errors on large tenants | Graph throttling. The script retries HTTP 429/503/504 with exponential backoff up to five attempts. Use `-Verbose` to confirm retries are happening rather than a hard failure. |
| `UsersMissingFromReport` is unexpectedly high | Report latency, or recently created users. Re-run after 24 to 48 hours before acting on the delta. |
| Empty CSV, zero migration candidates | Both SMS and voice are already disabled in AMP and no phone methods are registered. Verify against the portal, and check legacy per-user MFA settings separately. |
| Every user is `Moderate` | SMS and voice are disabled in AMP but phone numbers remain registered. This is the legacy per-user MFA pattern. |

---

## Development

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./tests
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

CI runs both on every push and pull request and fails on any finding.

The suite covers the risk model, AMP include/exclude resolution against a mocked Graph, both output-sanitization controls, the executive summary arithmetic, and the generated report's security properties. It also covers the repository's own structure: broken relative documentation links, `.gitignore` negations that no longer match where a file lives, and anything export-shaped committed outside `examples/` all fail the build. That last group is the defect class that shipped in 1.0.0 and was invisible to human review.

The assessment is a script rather than a module, so the tests parse it and lift out individual function definitions by name instead of dot-sourcing it, which would execute the Execution section and reach for Graph. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

This tool processes identity-security metadata. See [SECURITY.md](SECURITY.md).

**Never commit a real exported CSV, even to a private repository.** Exports contain UPNs, administrative status, registered authentication methods, and identity-security posture. The script belongs in source control; live tenant evidence belongs in your protected client documentation system. The `.gitignore` blocks the default output pattern, but the `.gitignore` is a safety net, not a control.

---

## References

- [Passkeys by default and retirement of Microsoft-provided SMS and voice authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement)
- [FAQ for Microsoft-provided SMS and voice retirement](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement-faq)
- [Choose a telephony provider for SMS and voice authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-phone-providers)
- [Microsoft's SMS/voice usage analyzer (official)](https://github.com/microsoft/entra-sms-voice-usage-analyzer)
- [Graph API: list userRegistrationDetails](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0)
- [Authentication methods activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)

Background and framework mapping: [docs/Microsoft-Migration-Background.md](docs/Microsoft-Migration-Background.md).

Running this at estate scale: [docs/Operations-Playbook.md](docs/Operations-Playbook.md).

---

## License

MIT. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Microsoft.
