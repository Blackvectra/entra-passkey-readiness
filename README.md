# entra-passkey-readiness

[![CI](https://github.com/Blackvectra/entra-passkey-readiness/actions/workflows/ci.yml/badge.svg)](https://github.com/Blackvectra/entra-passkey-readiness/actions/workflows/ci.yml)
[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7.0%2B-5391FE)](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
[![Read-only](https://img.shields.io/badge/Graph%20calls-GET%20only-0F9D6E)](#security)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Read-only PowerShell assessment that identifies which Microsoft Entra ID users are exposed to the retirement of Microsoft-provided SMS and voice authentication, and which are ready for passkeys.

It answers a question the Entra portal does not answer directly: **which specific users are both targeted by the SMS/voice Authentication Methods Policy and unable to satisfy MFA without it after the retirement date.**

Every Microsoft Graph call is a GET. It does not modify users, groups, policies, authentication methods, or registration campaigns, which is what makes it safe to run against a customer tenant during business hours without a change window.

---

## Table of contents

| Section | What it covers |
|---|---|
| [Overview](#overview) | The retirement timeline, and the two populations people conflate |
| [Components](#components) | The three scripts and what each one is for |
| [Prerequisites](#prerequisites) | Modules, roles, and Graph permissions |
| [Installation](#installation) | Getting the scripts onto a workstation that will run them |
| [Get started](#get-started) | The first run against one tenant |
| [Usage](#usage) | Estate sweeps, progress tracking, client reports, ticket queues |
| [Parameter reference](#parameter-reference) | Every parameter on all three scripts |
| [Output reference](#output-reference) | Console summary and CSV schema |
| [Risk classifications](#risk-classifications) | How the five bands are derived |
| [Who actually gets stopped](#who-actually-gets-stopped) | The lockout population, which is not the same as the risk bands |
| [Coverage](#coverage-who-this-actually-finds) | Exactly who this finds, and who it does not |
| [Legacy per-user MFA](#legacy-per-user-mfa) | The exposure the modern policy cannot see |
| [Service accounts](#service-accounts-and-shared-mailboxes) | Keeping non-human accounts out of the work queue |
| [Fixing what it finds](#fixing-what-it-finds) | A reviewed script, never an automatic write |
| [Troubleshooting](#troubleshooting) | Common failures and what they mean |
| [Known limitations](#known-limitations) | Read before presenting results to a client |
| [Contributing](#contributing) | Tests, linting, and the read-only contract |
| [Security](#security) | Handling tenant evidence |

Further reading, all in [docs/](docs):

| Document | What it covers |
|---|---|
| [Operations Playbook](docs/Operations-Playbook.md) | Running this across an estate: where the time goes, what to automate first, and the recurring loop |
| [Risk Classification](docs/Risk-Classification.md) | The full derivation of the five bands, and the control-framework mapping |
| [MFA Enforcement](docs/MFA-Enforcement.md) | Why a Conditional Access policy is not the same as MFA being enforced |
| [Microsoft Migration Background](docs/Microsoft-Migration-Background.md) | Microsoft's own timeline, and where SMS and voice can hide in a tenant |

---

## Overview

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
2. **Method registration** — users who have a phone number registered as an authentication method. This set drives who gets blocked on February 1.

This tool reports both, per user, in one pass, and classifies the intersection.

### Every place SMS and voice can live

The per-user rows are most of the picture, but not all of it. A run also checks every other area of the tenant where SMS or voice can be configured, and says explicitly which one it cannot reach:

| Area | Covered |
|---|---|
| SMS / voice authentication method policies (nested groups, exclusions) | ✅ Per-user scope resolution |
| SMS enabled as a **first-factor sign-in** method | ✅ Flagged per target — the portal enables this by default when SMS is switched on |
| What each user has registered | ✅ Per-user, including guests |
| Legacy per-user MFA (enabled/enforced) | ✅ Per-user, on every run |
| Legacy MFA **service settings** page and legacy **SSPR methods** page | ⚠️ No API exists. The run reads the policy migration state instead: anything short of `migrationComplete` means both pages still apply, and the console prints the exact portal paths to check |
| Authentication strengths permitting SMS/voice combinations | ✅ Named in the summary, with strengths that have *nothing else left* flagged as unsatisfiable |
| Conditional Access MFA enforcement | ✅ Inventory by name and state — whether any enabled policy requires MFA at all, and whether one grants through a retiring strength. Assignments/exclusions are not evaluated |

Out of scope by Microsoft's own definition: Azure AD B2C tenants (excluded from the retirement), Microsoft Entra External ID (separate retirement, announced later), and third-party MFA providers (unaffected unless the user is also enabled for Entra SMS/voice — which the per-user rows already catch).

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

## Components

| Script | Use it to |
|---|---|
| `Get-EntraSmsVoiceMigrationImpact.ps1` | Assess one tenant. This is the core of the project. |
| `Invoke-EntraSmsVoiceSweep.ps1` | Assess many tenants, with optional concurrency and resume. |
| `Compare-EntraSmsVoiceAssessment.ps1` | Diff two assessments to see whether the campaign is moving anybody. Reads files only; no Graph, no permissions. |

---

## Prerequisites

| Requirement | Detail |
|---|---|
| PowerShell | 7.0 or later (enforced by `#Requires`) |
| Module | `Microsoft.Graph.Authentication` (this is the only dependency) |
| Entra role | Global Reader or Security Reader |
| Network | Access to `graph.microsoft.com` |

> [!IMPORTANT]
> Run this as Global Reader or Security Reader, not Global Administrator. Nothing in the script needs a privileged role, and running it as one puts a privileged session on the workstation performing the assessment for no benefit.

### Delegated Graph permissions

All four scopes are read-only. The script requests them at connect time and will not proceed without them.

| Scope | Used for |
|---|---|
| `Policy.Read.All` | Authentication Methods Policy (method configuration, campaign and migration state), legacy per-user MFA state, authentication strengths, Conditional Access policies |
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

Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

`Microsoft.Graph.Authentication` is the only module required. The scripts call Graph over REST rather than through the resource-specific SDK modules, so there is nothing else to install and nothing to keep in version step.

### "cannot be loaded … is not digitally signed"

If the very first run stops with:

```
File ...\Get-EntraSmsVoiceMigrationImpact.ps1 is not digitally signed.
You cannot run this script on the current system.
```

nothing is wrong with the script or your account. You downloaded the repository as a **zip**, so Windows tagged every extracted file with the Mark of the Web, and your PowerShell execution policy refuses to run downloaded scripts that are not signed. Fix it step by step:

1. **Open PowerShell 7** (`pwsh`), not Windows PowerShell 5.1 — the scripts require 7.0+ and will refuse 5.1 anyway. If `pwsh` is not installed: `winget install Microsoft.PowerShell`, then open a new terminal.

2. **Go to the folder you extracted.** Note that extracting the zip usually creates a doubled folder — the scripts are in the *inner* one:

   ```powershell
   cd C:\Users\<you>\entra-passkey-readiness-main\entra-passkey-readiness-main
   ```

3. **Confirm the diagnosis** — this shows the download tag on each file:

   ```powershell
   Get-ChildItem *.ps1 | Get-Item -Stream Zone.Identifier -ErrorAction SilentlyContinue
   ```

   Output listing `Zone.Identifier` streams means the files are marked as downloaded.

4. **Remove the tag from everything in the folder** (recursive, so the tests and examples are covered too):

   ```powershell
   Get-ChildItem -Recurse | Unblock-File
   ```

5. **Check your execution policy:**

   ```powershell
   Get-ExecutionPolicy -List
   ```

   `RemoteSigned` is the policy this project expects: local and unblocked scripts run, unsigned downloads do not. If every scope reads `Undefined` or `Restricted`, set it for your user only — no admin rights needed:

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

6. **Run the script again:**

   ```powershell
   .\Get-EntraSmsVoiceMigrationImpact.ps1
   ```

If step 5 shows a policy set at `MachinePolicy` or `UserPolicy` scope (Group Policy), `Set-ExecutionPolicy` cannot override it — that is your organisation's endpoint policy doing its job. Options, in order of preference: clone with `git clone` instead of downloading a zip (cloned files carry no Mark of the Web, so `RemoteSigned` machines run them as local scripts); ask your endpoint team to allow the script; or run it from a machine not under that policy.

**Do not use `-ExecutionPolicy Bypass` as a habit.** It works, but it teaches you to disable a control instead of satisfying it, and this is a tool you may run on customer-facing machines.

---

## Get started

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1
```

That is the whole thing. A browser opens, you sign in as Global Reader or Security Reader, and you get two spreadsheets in a folder named for the tenant:

```
reports\Contoso\Contoso_2026-08-18.csv
reports\Contoso\Contoso_2026-08-18_ActionList.csv
```

| File | What it is |
|---|---|
| `<tenant>_<date>.csv` | The full assessment: one risk-ranked row per exposed user, highest risk first |
| `..._ActionList.csv` | The work list: affected users only, what they have, what to do, in plain language — no IDs. Attach it to a ticket ([sample](examples/Example-ActionList.csv)) |

Both open straight into Excel. Values that would otherwise be read as formulas are neutralised on the way out, so a display name beginning `=` cannot execute when somebody opens the file.

The folder name comes from `-CustomerName` when you pass it, the domain of the account you signed in with if you don't, and the tenant's GUID as a last resort. Running five clients back to back produces five folders you can tell apart at a glance, not five files distinguishable only by a timestamp. A re-run the same day overwrites that day's files; different days sit side by side. Pass `-CustomerName "Contoso Manufacturing"` when the sign-in domain does not read as the client's name:

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -CustomerName "Contoso Manufacturing"
```

Use `-OutputPath` if you want the files somewhere else entirely; everything else is named from it.

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

Results sort failures first, then tenants whose result is a lower bound and shows nothing, then by how many users are blocked at the retirement, then by risk band. The estate triage order is the read order.

> [!IMPORTANT]
> `AssessmentConfidence` says whether a tenant's zeroes can be read as "nothing found". `Complete` means the authentication methods policy is fully migrated, so the modern policy read is the whole answer. `LowerBound` means it is not, and the legacy per-user MFA service settings and legacy SSPR methods pages still govern that tenant — both can hand out SMS and voice through settings no API exposes. A `LowerBound` tenant reporting zero has been partially measured, not measured clean, so those tenants are lifted above the genuinely clean ones and named on the console rather than left at the bottom of the file where the usual "open the non-zero rows" habit skips them.

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

Every row is written against one fixed column list, whichever run produced it. `Export-Csv` takes its header from the first object it receives, so a carried-forward row from an older build sorting to the top would otherwise drop the newer columns from every row in the file — and since that truncated file then becomes the newest summary, the next resume would read the short schema and truncate again. Columns a row does not carry are written empty, which reads correctly as "this tenant was never assessed on that field".

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

- **The file you attach to a ticket you raised yourself.** Seven columns, in plain language rather than Graph's enum spellings, and no object IDs: `Priority`, `User`, `SignIn`, `LastSignIn`, `Has`, `Problem`, `DoThis`. `Has` reads `Phone + Authenticator` instead of `mobilePhone; microsoftAuthenticatorPush`. `Priority` sorts the queue: `1 - Lockout` (stops working 2027-02-01) ahead of `2 - Admin`, `3 - Migrate`, and `4 - Likely leaver` (stale or never signed in — check before chasing). Everything a technician needs to work the queue top-down, and none of the diagnostic columns that make the full export wide.
- **The membership list** for the migration security group Microsoft's guidance tells you to create as step one, ready for bulk import on `SignIn` (the user's sign-in name/UPN).

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

A tenant with `All users` targeting can produce hundreds of High findings. Ticketing each one creates a backlog nobody works, so the overflow becomes a campaign ticket that points at the action list CSV.

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

The history file holds object IDs and risk bands only, no names and no UPNs, so it can sit wherever is convenient without carrying identifying data.

**One thing to get right.** The history defaults to a file beside the ticket CSV. If you write to dated output folders, which the [playbook](docs/Operations-Playbook.md) recommends, each run lands somewhere new and finds no history, so every run looks like a first run. Point `-TicketHistoryPath` at a stable path per customer:

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
    -OutputPath "D:\ClientEvidence\Contoso\$(Get-Date -f yyyy-MM-dd)\contoso.csv" `
    -ExportTickets -TicketHistoryPath 'D:\ClientEvidence\Contoso\TicketHistory.json'
```

The sweep does this for you: history lives in the per-tenant folder rather than the dated run folder, so a repeat sweep across the estate is already deduplicated.

`-IgnoreTicketHistory` raises tickets for everyone regardless, for rebuilding a queue that was lost. `TicketsSuppressedAsAlreadyRaised` in the summary tells you how many were held back, so a near-empty queue reads as "already ticketed" rather than "assessment found nothing".

---

## Parameter reference

### `Get-EntraSmsVoiceMigrationImpact.ps1`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-TenantId` | string | current Graph context | Tenant GUID or verified domain — **not** a sign-in name, though a UPN is accepted and its domain used. Omit it to sign in interactively. Forces re-auth if it does not match the live session. Mandatory for app-only. |
| `-ClientId` | string | none | App registration ID for unattended app-only auth, validated as a GUID. Requires `-CertificateThumbprint`. |
| `-CertificateThumbprint` | string | none | Certificate thumbprint for app-only auth. |
| `-OutputPath` | string | timestamped CSV beside the script, with `-CustomerName` folded in | Destination CSV path. The report and action list are named from it. Parent directory is created if missing. |
| `-IncludeUnaffected` | switch | off | Include every enabled user, not just migration candidates. |
| `-ExportFixScript` | switch | off | Also writes a `..._Remediation.ps1` of commands for you to review and run yourself. The assessment still writes nothing to any tenant, and the generated file refuses to run until you read it. See [Fixing what it finds](#fixing-what-it-finds). |
| `-SkipLegacyPerUserMfa` | switch | off | **Skips** the legacy per-user MFA read, which every run otherwise performs. Only worth setting to avoid the beta endpoint entirely; it costs you the assessment's one real blind spot. See [Legacy per-user MFA](#legacy-per-user-mfa). |
| `-ExcludeUpnPattern` | string[] | none | Regex patterns matched against the UPN. Matching users are marked `Excluded` and left out of every count and work queue. See [Service accounts](#service-accounts-and-shared-mailboxes). |
| `-HtmlReport` | switch | off | Also write a self-contained HTML client report beside the CSVs. |
| `-CustomerName` | string | sign-in domain | The client's name. Sets the output folder name, the heading on the HTML report, and the `Company` field on every exported ticket, so five clients assessed back to back produce five folders you can tell apart. |
| `-ExportTickets` | switch | off | Also write a PSA-importable ticket queue. |
| `-MaxIndividualTickets` | int | 50 | Cap on individual tickets before High findings batch into a campaign ticket. |
| `-TicketHistoryPath` | string | beside the ticket CSV | Users already ticketed, so a re-run does not raise duplicates. See [Re-running without duplicating tickets](#re-running-without-duplicating-tickets). |
| `-IgnoreTicketHistory` | switch | off | Ticket every actionable user regardless of previous runs. |
| `-SkipAclHardening` | switch | off | Skip restricting output file permissions. Use only where the filesystem rejects ACL changes. |
| `-PassThru` | switch | off | Emit per-user objects to the pipeline in addition to the summary. |

### `Invoke-EntraSmsVoiceSweep.ps1`

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

### `Compare-EntraSmsVoiceAssessment.ps1`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-BaselinePath` | string | **required** | The earlier assessment CSV. |
| `-CurrentPath` | string | **required** | The later assessment CSV. |
| `-OutputPath` | string | timestamped CSV beside `-CurrentPath` | Destination for the change report. |
| `-IncludeUnchanged` | switch | off | Include users whose band did not move. |
| `-SkipAclHardening` | switch | off | Skip restricting output file permissions. |
| `-PassThru` | switch | off | Emit per-user change objects to the pipeline. |

---

## Output reference

### Console summary

| Field | Meaning |
|---|---|
| `TenantId` | Tenant the assessment actually ran against |
| `DirectoryUsersReturned` / `EnabledUsersAssessed` / `UsersSkippedNotEnabled` | The assessment's own arithmetic. The last two must sum to the first — that is what makes a silently dropped user visible instead of invisible. |
| `RegistrationCampaignState` | `enabled`, `disabled`, `default (Microsoft managed)`, or `unknown` when the policy read returned no state |
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
| `DaysSinceLastSignIn` | int or marker | Whole days since the last successful sign-in. `(none recorded)` means never, or not since April 2020 — Microsoft keeps no history before then. `(not available)` means the tenant is not licensed to report sign-in activity (Entra ID P1/P2). **A name on a work queue that has not signed in for a year is a deprovisioning ticket, not a passkey one.** |
| `PerUserMfaState` | string | `disabled`, `enabled`, or `enforced` from legacy per-user MFA; `(not checked)` if `-SkipLegacyPerUserMfa` was set; `(unreadable)` if Graph would not answer. Always written, so the column never appears and disappears between runs. |
| `PhoneMethodsRegistered` | string | Semicolon-delimited subset of the retiring methods: `mobilePhone`, `alternateMobilePhone`, `officePhone`, `smsSignIn`, plus the older enum spellings `sms`, `mobileSMS`, `mobileCall`, and `alternateMobileCall`. Both generations are matched, because which one a tenant's report returns is not something to discover on the day. |
| `AllMethodsRegistered` | string | Every method reported for the user, or `(no row in registration report)` when the report had no data for them. |
| `PreferredMethod` | string | What the sign-in prompt defaults to today — a different question from what is merely registered. `(no row in registration report)` mirrors `AllMethodsRegistered`; `None set` means nothing in the classic second-factor list applies (a passkey-only user, typically). See [below](#preferred-method-vs-registered-methods). |
| `IsPasswordlessCapable` | bool | Reports a passwordless method. This is the mitigating control. |
| `UserId` | guid | Object ID. Kept last because it is a join key, not something you read. |

Seventeen columns, sorted highest risk first, then admins ahead of standard users, then display name.

The registration report also returns `isMfaCapable`, `isMfaRegistered`, and a per-row timestamp. None of them changed what anybody did with the file, so they are not written. Evidence age is still reported once, as `OldestReportRowUtc` in the summary, and a user with no report row is called out in `AllMethodsRegistered` and `PreferredMethod` rather than needing a column of its own.

### Preferred method vs. registered methods

`BlockedAtRetirement` answers "does this user have anything left to sign in with." It does not answer a different question a real tenant surfaced: a user can hold Microsoft Authenticator, so they are not blocked, and still be shown a text message every time they sign in, because Entra decides the default sign-in prompt from one of two unrelated fields:

- **System-preferred MFA is on** (`isSystemPreferredAuthenticationMethodEnabled`): Entra recalculates the strongest registered method live. This cannot get stuck on SMS once a better method exists.
- **System-preferred MFA is off**: the user's own choice, made once and never revisited. Somebody who registered Authenticator last year can still default to SMS today, and nothing prompts them to change it before the method disappears on 2027-02-01.

`PreferredMethod` reads whichever of the two applies. `UsersDefaultingToPhonePrompt` in the summary counts everyone whose default is SMS or voice **and** who is not already caught by `BlockedAtRetirement` — the population that will not be locked out, but will hit a confusing, unexplained sign-in prompt on the retirement date instead. Have them set a different default in **Security Info** before then.

---

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
| Non-human accounts | Shared mailboxes, sync accounts, and service accounts appear as ordinary users | Filter by your naming convention with `-ExcludeUpnPattern`, or drop them from the action list after review |

That last one matters operationally. A tenant with `All users` targeting will surface shared mailbox and service account objects as migration candidates. They are technically in scope but nobody signs into them interactively, so review before they become tickets.

---

## Legacy per-user MFA

The one exposure this assessment can otherwise miss entirely.

Legacy per-user MFA is a separate enforcement layer that predates the Authentication Methods Policy and is not replaced by it. A user `enabled` or `enforced` there is in scope for the SMS and voice retirement whatever the modern policy says — and the modern registration campaign does not reach them, so a passkey push aimed at that user lands nowhere and the run after this one reports them unchanged.

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com
```

Every run reads this state by default. Opting out with `-SkipLegacyPerUserMfa` leaves those users surfacing as `Moderate` with an instruction to go and check a portal by hand. Across an estate that is one manual check per tenant that does not happen, and a tenant still running on legacy per-user MFA assesses as unremarkable.

**It needs no extra access.** The state is readable at `GET /beta/users/{id}/authentication/requirements` with `Policy.Read.All`, which every run already requests, and Global Reader is a supported role. The only reason to skip it is to avoid the beta endpoint entirely, not permission. The cost is one batched Graph call per twenty users.

What the check changes:

| | With `-SkipLegacyPerUserMfa` | Default run |
|---|---|---|
| `PerUserMfaState` | `(not checked)` on every row | `disabled`, `enabled`, `enforced`, or `(unreadable)` |
| A user held in legacy MFA | `Moderate`, "go and check a portal" | The band their real exposure earns, up to `Critical`, with a next step that starts by converting them to the modern policy |
| A `Moderate` user who is genuinely clear | Indistinguishable from the above | Confirmed stale registration, no portal visit |
| Summary | — | `LegacyPerUserMfaChecked`, `LegacyPerUserMfaInForce`, `LegacyPerUserMfaUnreadable` |

**Not knowing never looks like knowing.** A denied read, a request Graph left unanswered, and a `200` with no state in the body all land as `(unreadable)`, counted in `LegacyPerUserMfaUnreadable`. None of them is ever treated as "no legacy MFA," because that reading is indistinguishable from a genuine all-clear, and it is exactly the one that leaves somebody locked out with a clean report on file. A throttled request inside a batch returns `200` at the envelope level, so nothing above the per-request loop would retry it on its own; the script retries it across rounds instead of giving up.

A non-zero `LegacyPerUserMfaInForce` is also an MFA enforcement finding in its own right: per-user MFA sitting underneath a Conditional Access policy has its own trusted-IP bypass and its own remembered-device setting, neither of which Conditional Access knows about. See [docs/MFA-Enforcement.md](docs/MFA-Enforcement.md).

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

## Fixing what it finds

The assessment writes nothing to any tenant, and that does not change. What `-ExportFixScript` adds is a **file**:

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.org -ExportFixScript
```

You get `..._Remediation.ps1` beside the CSVs: one commented block per actionable user, with the exact Graph calls. Nothing in it has run, and it opens with a `throw` so running it unread does nothing at all. Every command that would change the tenant is commented out.

**The central remediation cannot be automated, by anyone.** No Graph call registers a passkey on somebody's behalf; registration requires the user present with their device. That is the point of a passkey. What the script automates is the supporting cast, and the order is the whole value:

1. **Issue a Temporary Access Pass.** This is what lets somebody register a passkey *without* the phone they are about to lose. Skip it and you strand exactly the people you were trying to help.
2. **The user registers.** A human step. The script says so and stops.
3. **Verify the new method exists.**
4. **Only then remove the phone method.** This line is commented out and it is last, because removing a phone before a replacement is confirmed working is precisely the lockout this whole tool exists to prevent.

The commands need `UserAuthenticationMethod.ReadWrite.All` and `Policy.ReadWrite.AuthenticationMethod` — write permissions, well beyond the read-only set the assessment ran with. That escalation is yours to make deliberately.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `...is not digitally signed. You cannot run this script on the current system.` | The repo was downloaded as a zip, so the files carry the Mark of the Web and the execution policy refuses them. Step-by-step fix in [Installation](#cannot-be-loaded--is-not-digitally-signed): `Get-ChildItem -Recurse \| Unblock-File`, then confirm the policy is `RemoteSigned`. |
| `Microsoft.Graph.Authentication is required but is not installed.` | Run `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`. |
| Sign-in succeeds but results are for the wrong tenant | A cached Graph session was reused. Run `Disconnect-MgGraph`, then re-run with an explicit `-TenantId`. |
| `Insufficient privileges to complete the operation` on the reports endpoint | `AuditLog.Read.All` was not consented. Have an admin consent to all four delegated scopes. |
| `No enabled users were returned` | The signed-in account lacks `User.Read.All`, or is signed in to a tenant with no enabled users. |
| Run is slow or intermittently errors on large tenants | Graph throttling. The script retries HTTP 429/503/504 with exponential backoff up to five attempts. Use `-Verbose` to confirm retries are happening rather than a hard failure. |
| `UsersMissingFromReport` is unexpectedly high | Report latency, or recently created users. Re-run after 24 to 48 hours before acting on the delta. |
| Empty CSV, zero migration candidates | Both SMS and voice are already disabled in AMP and no phone methods are registered. Verify against the portal, and check legacy per-user MFA settings separately. |
| Every user is `Moderate` | SMS and voice are disabled in AMP but phone numbers remain registered. This is the legacy per-user MFA pattern. |

---

## Known limitations

These are properties of the data sources, not defects. Read them before presenting results to a client.

- **Disabled users are excluded.** `userRegistrationDetails` does not return disabled users. The script reads `accountEnabled` separately and assesses enabled users only. Disabled accounts that get re-enabled after the assessment are not represented.
- **Reporting latency.** The registration report is not real-time. `OldestReportRowUtc` in the summary is the age of the oldest row behind the assessment, so the confidence in a run is visible. Do not treat a run as a live directory query.
- **SMS and voice are not separately registered.** Entra stores a phone number with a type, not an "SMS registration" and a "voice registration." `mobilePhone` can satisfy both; `officePhone` is voice-only. There is no clean per-user SMS-versus-voice split available, so the script reports phone-method capability and leaves policy scope to distinguish intent.
- **Legacy per-user MFA is read from a beta endpoint.** Users enabled for SMS or voice through legacy per-user MFA service settings are in scope for the retirement, and that state has no Graph v1.0 equivalent — it exists only at `/beta/users/{id}/authentication/requirements`. Every run reads it, using the `Policy.Read.All` the script already requests. `-SkipLegacyPerUserMfa` opts out, and then `PerUserMfaState` reads `(not checked)` on every row and that exposure is unassessed.
- **Conditional Access is not evaluated.** A user may be in AMP scope but never challenged, or may be blocked by a Conditional Access grant this script does not read. Policy scope is not the same as effective sign-in behaviour, and it is not the same as MFA being enforced at all — see [docs/MFA-Enforcement.md](docs/MFA-Enforcement.md) for the ten common reasons a tenant with a Require-MFA policy is not actually requiring MFA.
- **Guest and B2B readiness.** Guests are assessed, but passkey support for B2B and internal guest users is on a separate Microsoft timeline. Treat guest findings as requiring independent validation.
- **Nested groups are resolved transitively; dynamic groups are point-in-time.** A dynamic group's membership can change between the assessment and September 1.

---

## Contributing

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./tests
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

CI runs both on every push and pull request and fails on any finding.

The suite covers the risk model, AMP include/exclude resolution against a mocked Graph, both output-sanitization controls, the executive summary arithmetic, and the generated report's security properties. It also covers the repository's own structure: broken relative documentation links, `.gitignore` negations that no longer match where a file lives, and anything export-shaped committed outside `examples/` all fail the build. That last group is the defect class that shipped in 1.0.0 and was invisible to human review.

The assessment is a script rather than a module, so the tests parse it and lift out individual function definitions by name instead of dot-sourcing it, which would execute the Execution section and reach for Graph. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

This tool processes identity-security metadata. See [SECURITY.md](SECURITY.md).

**Never commit a real exported CSV, even to a private repository.** Exports contain UPNs, administrative status, registered authentication methods, and identity-security posture. The script belongs in source control; live tenant evidence belongs in your protected client documentation system. The `.gitignore` blocks the default output pattern, but the `.gitignore` is a safety net, not a control.

---

## Related resources

- [Passkeys by default and retirement of Microsoft-provided SMS and voice authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement)
- [FAQ for Microsoft-provided SMS and voice retirement](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement-faq)
- [Choose a telephony provider for SMS and voice authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-phone-providers)
- [Microsoft's SMS/voice usage analyzer (official)](https://github.com/microsoft/entra-sms-voice-usage-analyzer)
- [Graph API: list userRegistrationDetails](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0)
- [Authentication methods activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)

Microsoft's timeline and where SMS and voice hide in a tenant: [docs/Microsoft-Migration-Background.md](docs/Microsoft-Migration-Background.md).

Control-framework mapping (NIST CSF 2.0, SP 800-53, SP 800-63B, CIS v8): [docs/Risk-Classification.md](docs/Risk-Classification.md#framework-mapping).

Running this at estate scale: [docs/Operations-Playbook.md](docs/Operations-Playbook.md).

---

## License

MIT. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Microsoft.
