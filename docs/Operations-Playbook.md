# Operations Playbook

How to run this assessment across an estate without it becoming a full-time job, and where the time actually goes.

This is written for the multi-tenant case. If you manage one tenant, read the [Cadence](#cadence) section and ignore the rest.

---

## Where the time actually goes

Before optimising anything, it is worth being honest about the cost distribution. On a ninety-tenant estate the assessment itself is not the bottleneck.

| Step | Typical cost | Can this tool help? |
|---|---|---|
| Getting app-only auth consented in each tenant | **Days to weeks**, one time | No. This is a write and a customer conversation. |
| Running the assessment | Minutes per tenant, parallelisable | Yes, this is what it does |
| Reviewing candidates and filtering non-human accounts | Hours, first run; minutes after | Partly, see [Service accounts](#service-accounts-and-shared-mailboxes) |
| Validating legacy per-user MFA | Hours, manual, per tenant | No. Not readable at this permission level. |
| Creating remediation groups and campaigns | Minutes per tenant | Produces the list; the group is a write you make |
| Client communications | Hours per client | No |
| Tracking progress across re-runs | Was hours; now minutes | Yes, `Compare-EntraSmsVoiceAssessment.ps1` |

**The single highest-leverage thing you can do is finish app-only onboarding early.** Everything downstream is gated on it, and it is the only step whose cost does not fall with practice. Until it is done, every sweep needs one interactive sign-in per tenant and cannot be parallelised or scheduled.

---

## One-time setup

### 1. App registration and consent

Register one application and consent to it in every managed tenant. The four permissions are required as **application** permissions, and all four are read-only:

`Policy.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`

Send each customer's Global Administrator an admin consent URL rather than talking them through the portal:

```
https://login.microsoftonline.com/{tenant}/adminconsent?client_id={your-app-id}
```

Use a certificate, not a client secret. The tool refuses secrets deliberately: a credential that can read identity posture across an entire customer estate should not be a string in a parameter.

**Do not add the write permission to this app.** `Set-EntraPasskeyOptOut.ps1` needs `Policy.ReadWrite.AuthenticationMethod` as an application permission, and that is the only thing in this project that does. Consenting to it alongside the four read scopes would mean every routine sweep across the estate runs holding a credential that can rewrite an authentication policy. Register it separately, and consent to it only in the tenants you have actually decided to defer. See [The 14-day decision](#the-14-day-decision-who-to-defer).

Track consent state in your tenant list so you know which customers are ready:

```csv
TenantId,CustomerName
contoso.onmicrosoft.com,Contoso Manufacturing
fabrikam.onmicrosoft.com,Fabrikam Logistics
```

A tenant that has not consented fails its row in the sweep with a clear error and does not stop the run. That failure list *is* your onboarding backlog. Work it top-down.

### 2. Evidence store

Point `-ReportRoot` at your protected client documentation store. Never at a git working directory, a synced folder with broad sharing, or anywhere a general-purpose search index reaches.

Every file this tool writes is a targeting list: it names privileged accounts and states which of them lack a phishing-resistant method. Treat exports the way you treat a penetration test report.

### 3. A baseline, early

Run the whole estate once before you change anything. Everything after this is measured against it, and the diff is only as good as the baseline.

```powershell
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
    -ReportRoot D:\ClientEvidence\EntraMigration\baseline `
    -ClientId <app-id> -CertificateThumbprint <thumbprint> `
    -ThrottleLimit 6 -HtmlReport
```

Keep the baseline folder immutable. Later runs go elsewhere.

---

## The recurring loop

Once onboarding is done, each cycle is four steps.

### 1. Sweep

```powershell
$stamp = Get-Date -Format 'yyyy-MM-dd'
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
    -ReportRoot "D:\ClientEvidence\EntraMigration\$stamp" `
    -ClientId <app-id> -CertificateThumbprint <thumbprint> `
    -ThrottleLimit 6 -HtmlReport
```

**On `-ThrottleLimit`.** Six is a reasonable default. Graph throttles per tenant, so concurrency across different tenants does not compound it, but each concurrent tenant is a separate pwsh process holding a Graph session, so the ceiling is your machine rather than Microsoft's. Raising it will not make a single large tenant faster; nothing will, short of Microsoft's own pagination.

**If it dies partway**, re-run the identical command with `-Resume` added. Tenants already recorded as `Success` are skipped and carried into the new summary.

### 2. Diff, do not re-read

This is the step that saves the most time, and the one most likely to get skipped.

```powershell
.\Compare-EntraSmsVoiceAssessment.ps1 `
    -BaselinePath "...\baseline\Contoso\...Impact.csv" `
    -CurrentPath  "...\$stamp\Contoso\...Impact.csv"
```

Read `Regressed` first. A user who went backwards means something is actively wrong: a removed method, a reset account, or a group membership change that pulled somebody into policy scope. `LeftActionableBands` is the number worth putting in a client status update.

Do not re-read the full export every cycle. On a 400-row assessment, 380 rows will be identical to last month and reading them all is how a monthly cadence quietly becomes a quarterly one.

### 2b. Check the lockout number first

Before reading anything else, look at `BlockedAtRetirement` in each tenant's summary. That is the count of users whose only MFA method is a phone number, and it is the count of people who cannot work on the morning of 2 February 2027 until they complete a passkey registration they cannot skip.

It is **not** the same as the risk bands, and it does not track them. A `High` user holding Microsoft Authenticator push is not stopped, because Authenticator is not being retired. A `Moderate` user whose only method is an office phone *is* stopped, despite sitting two bands lower.

Work this number down first, then work the bands. If you only ever fixed the users in this count, nobody would be locked out — everything else is about getting the estate to a phishing-resistant posture, which matters but does not have a Monday morning attached to it.

Two populations inside it deserve separate handling:

- **Privileged accounts** (`BlockedAdminsAtRetirement`). If one of these is stopped and its recovery path is also a phone number, the tenant has an availability problem, not just a sign-in problem.
- **Anyone who cannot register on the spot.** The blocking prompt assumes the user can complete passkey registration at that moment. Somebody on a shared terminal, on an unsupported device, or calling the help desk from an airport cannot. This tool cannot see device capability, so that population has to come from your own asset data.

### 3. Act on the delta

| What the diff shows | What to do |
|---|---|
| `BlockedAtRetirement` above zero | Work it before the bands. These are the people who stop working on the date. |
| `Regressed`, any privileged account | Investigate today. This is the lockout scenario in progress. |
| `Regressed`, standard users | Check whether a group membership change pulled a population into scope. |
| `New` | Usually new starters. Confirm your joiner process registers a passkey at onboarding, or this queue refills forever. |
| `Improved` / `Resolved` in bulk | The campaign is working. Report the number and keep going. |
| Nothing moved | The campaign is not reaching people. Change the communication, not the cadence. |

### 4. Report

The per-tenant HTML report is client-ready as generated. Send it, or print it to PDF and attach it to your monthly report.

---

## Cadence

Work backwards from the two dates that matter.

| Period | Frequency | Why |
|---|---|---|
| Now until 2026-09-01 | **Weekly** | The auto-enablement and nudge land on 1 September. Anything you fix before then is a help-desk ticket that never happens. |
| 2026-09-01 to 2026-12-01 | **Fortnightly** | Campaign is running; you are tracking completion, not discovering scope. |
| 2026-12-01 to 2027-02-01 | **Weekly**, and daily on Critical | The remaining population is the hard tail: shared accounts, executives, people who snoozed the nudge fifty times. |
| After 2027-02-01 | Monthly | New starters and re-enabled accounts still need catching. |

The 1 September date is a rollout, not a switch. Microsoft describes it as phased, so the date it reaches a given tenant varies. Do not treat a quiet 2 September as evidence you were out of scope.

---

## The 14-day decision: who to defer

Two weeks out from 1 September there is one decision to make per tenant, and it is not "should we opt out". It is **which few tenants get deferred and which get nudged**, because on most of them the nudge does work you would otherwise do by hand.

### 1. Sweep, then read two columns

```powershell
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
    -ReportRoot "D:\ClientEvidence\EntraMigration\pre-september" `
    -ClientId <app-id> -CertificateThumbprint <thumbprint> -ThrottleLimit 6
```

Read `AssessmentConfidence` **first**, before any count in the row.

- **`LowerBound`** — the numbers beside it are floors. Legacy per-user MFA is still authoritative in that tenant and this tool cannot see it, so a low `BlockedAtRetirement` there is not evidence of low exposure. Do the manual legacy-MFA check before deciding anything about that tenant. Deferring, or not deferring, on the strength of a `LowerBound` zero is the exact mistake this column exists to prevent.
- **`Complete`** — `BlockedAtRetirement` is a real number and you can act on it.

Then read `BlockedAtRetirement` and `BlockedAdminsAtRetirement`. Those are the people stopped at sign-in on 2 February 2027, and they are what the September nudge is trying to fix for you at no cost.

### 2. Defer the few, nudge the rest

Three shapes are worth deferring:

| Shape | Why |
|---|---|
| Frontline and shared-device populations | The nudge assumes the user can complete passkey registration at that moment. Somebody on a shared terminal, a kiosk, or an unsupported handset cannot, so the prompt produces a help-desk call rather than a registration. This tool cannot see device capability; that population comes from your own asset data. |
| Tenants mid-project | A tenant move, an Intune rollout, an MFA project already in flight. A second unscheduled change landing on the same users in the same fortnight is how both slip. |
| Panic-prone clients | You know which ones. A client who escalates on an unannounced prompt costs more in one afternoon than the deferral costs over five months. Defer, communicate, then re-arm on your own schedule. |

Everything else gets nudged. A tenant with a manageable `BlockedAtRetirement`, nothing in flight, and users on their own managed devices is a tenant where 1 September works in your favour.

```powershell
.\Set-EntraPasskeyOptOut.ps1 -TenantListPath .\defer-these.csv `
    -ClientId <app-id> -CertificateThumbprint <thumbprint> `
    -Direction OptOut -ResultPath D:\ClientEvidence\deferred.csv -WhatIf
```

`-WhatIf` first: it still connects and reads, so the Before column is real. Then re-run without it. Always pass `-ResultPath` — without it the only record of which tenants you deferred is console scrollback, and in January that list is the thing you need.

### 3. What deferring actually costs

Opting out buys runway on one date and nothing else.

- **It does not move 2027-02-01.** The retirement and the blocking prompt are not opt-outable. Deferring does not lengthen the migration window, it **compresses** it: the work still has to finish by February, and you have taken five months off the front of it.
- **It removes the free adoption pressure.** The 1 September nudge is the largest driver of unprompted passkey registration you will get, and it costs you nothing. Turn it off and every registration after that is one your comms and your help desk have to produce.
- **It is a write into a customer tenant.** It belongs in the change record like any other, and it needs `Policy.ReadWrite.AuthenticationMethod` as an application permission, which the assessment app deliberately does not hold.

The honest version: defer where an unannounced prompt would cause a real operational problem, and accept that you have bought a quieter September in exchange for a busier January. If you defer a tenant, put the re-arm and the campaign start in the calendar the same day, or the deferral quietly becomes the plan.

Re-run the assessment afterwards to confirm the state. `PasskeyOptedOut` is the column, and `read-failed` is not `false` — a tenant you deferred in August that reads `read-failed` in December has not been confirmed as still deferred, it has failed to be read.

---

## Things that will slow you down

### Service accounts and shared mailboxes

A tenant with `All users` targeting surfaces every shared mailbox, sync account, and service account as a migration candidate. They are technically in scope and nobody signs into them interactively, so ticketing them wastes a technician's afternoon.

The tool does not filter them, because a naming convention that is obvious in your estate is not inferable in general. Filter at the pipeline:

```powershell
$rows = .\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com -PassThru
$real = $rows | Where-Object { $_.UserPrincipalName -notmatch '^(svc-|shared-|noreply)' }
$real | Where-Object Risk -eq 'Critical' | Format-Table DisplayName, UserPrincipalName, PhoneMethodsRegistered
```

Do this **before** generating tickets, not after. Reviewing the exclusions once per customer and recording the pattern in your runbook turns an hours-long first pass into a thirty-second one on every later run.

### Ticket history, and the one way to get it wrong

Re-runs no longer duplicate tickets. The run records which users it ticketed, and a later run raises one only for a user who is new or whose risk band got worse. Somebody who was High last month and is High today is already in a queue.

The one way to lose that: the history file defaults to sitting beside the ticket CSV, and this playbook recommends writing each run to a dated folder. Those two together mean every run lands somewhere new, finds no history, and behaves like a first run.

The sweep handles it — history lives in the per-tenant folder rather than the dated run folder. For single-tenant runs, point `-TicketHistoryPath` at something stable:

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
    -OutputPath "D:\ClientEvidence\Contoso\$stamp\contoso.csv" `
    -ExportTickets -TicketHistoryPath 'D:\ClientEvidence\Contoso\TicketHistory.json'
```

Check `TicketsSuppressedAsAlreadyRaised` in the summary. If it is zero on a second run against an unchanged tenant, the history is not being found.

The file holds object IDs and risk bands only, so it carries no identifying data and can live wherever is convenient. Back it up with the evidence: losing it means the next run re-raises everything.

### Legacy per-user MFA

Users enabled for SMS or voice through legacy per-user MFA service settings are in scope for the retirement and are **not readable** at the permission level this tool runs at. Reading them needs permissions beyond the four read-only ones, which would break the least-privilege model that makes the tool safe to run unattended across an estate.

You no longer have to infer which tenants this applies to. `AssessmentConfidence` in the sweep summary says it outright: `LowerBound` means `policyMigrationState` is not `migrationComplete`, the legacy service is still authoritative there, and every count in that row **understates** the exposure. Those rows sort near the top of the summary when they show no findings, because a `LowerBound` zero is the most misleading number in the file.

A large `Moderate` count is the corroborating signal. Budget a manual check per tenant in the legacy MFA portal, once, early. A tenant with a high Moderate count and SMS disabled in the modern policy is the classic legacy-MFA shape.

Do not report a zero-candidate tenant as finished until this check is done. On a `LowerBound` tenant, "zero candidates" means "not measured".

**One beta call, and it is a read.** For completeness: the assessment does make a single GET against `beta/policies/authenticationMethodsPolicy`, because `optOutSettings.passkeyDynamicMigration` — the September opt-out flag — is not on the v1.0 surface. It needs no extra permission, changes nothing, and degrades to `PasskeyOptedOut = read-failed` if the endpoint is unavailable. Legacy per-user MFA remains unread; that is a scope decision, not an endpoint one.

### Reporting latency

The registration report is not a live directory query. `OldestReportRowUtc` in the summary is the honest confidence marker for a run.

Practical consequence: after a registration campaign starts, do not expect the numbers to drop immediately, and do not re-run daily hoping they will. Give it 24 to 48 hours. A user who registered a passkey this morning may still read as exposed tonight.

### Interactive sign-in

One prompt per tenant, and it cannot be scheduled, parallelised, or left unattended. If you are still signing in interactively for an estate sweep, the fix is not a faster script. It is finishing the app-only onboarding.

---

## What to automate, in order

1. **The sweep.** Scheduled task or pipeline, app-only auth, `-ThrottleLimit`, output to a dated folder. This is the easy win.
2. **The diff.** Chain `Compare-EntraSmsVoiceAssessment.ps1` onto the sweep so the change report is waiting for you rather than something you remember to run.
3. **The alert.** Have the automation surface only two numbers: count of `Regressed`, and count of Critical across the estate. Both should be zero or falling. Anything else is a dashboard nobody opens.
4. **Nothing else, yet.** Group creation and campaign configuration are writes into customer tenants. Automating those is a different risk conversation from automating a read, and it should be a deliberate decision rather than a natural next step. `Set-EntraPasskeyOptOut.ps1` is a write too, and it stays on this list: it is a script you run at a keyboard against a list you chose, not a step you chain onto the sweep.

---

## Suggested improvements to the tool

Gaps worth knowing about, roughly in order of how much time each would save an estate-scale operator.

| Idea | Why it would help |
|---|---|
| `-ExcludeUpnPattern` parameter | Every operator writes the same `Where-Object` filter for service accounts. Making it a parameter puts it in the ticket and action-list paths too, not just the pipeline. |
| Estate-wide HTML report | Reports are per-tenant today. A single roll-up ranking customers by Critical count is what an account manager actually wants. |
| Legacy per-user MFA read behind an explicit opt-in switch | Would close the largest coverage gap — the one `AssessmentConfidence = LowerBound` currently only flags — at the cost of broader scopes. Opt-in keeps the least-privilege default intact. |
| Trend series rather than pairwise diff | The diff compares two runs. Ten runs plotted would show whether a campaign is decelerating, which is the thing you want to catch early. |

---

## Related

- [README](../README.md) — installation, parameters, output schema
- [Risk-Classification.md](Risk-Classification.md) — how the five bands are derived
- [Microsoft-Migration-Background.md](Microsoft-Migration-Background.md) — the timeline and framework mapping
- [SECURITY.md](../SECURITY.md) — handling exports
