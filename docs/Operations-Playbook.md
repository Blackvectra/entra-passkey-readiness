# Operations Playbook

How to run this assessment across an estate without it becoming a full-time job, and where the time actually goes.

This is written for the multi-tenant case. If you manage one tenant, read the [Cadence](#cadence) section and ignore the rest.

---

## Where the time actually goes

Before optimizing anything, it is worth being honest about the cost distribution. On a ninety-tenant estate the assessment itself is not the bottleneck.

| Step | Typical cost | Can this tool help? |
|---|---|---|
| Getting app-only auth consented in each tenant | **Days to weeks**, one time | No. This is a write and a customer conversation. |
| Running the assessment | Minutes per tenant, parallelisable | Yes, this is what it does |
| Reviewing candidates and filtering non-human accounts | Hours, first run; a parameter after | Yes, once you know the convention: [Service accounts](#service-accounts-and-shared-mailboxes) |
| Validating legacy per-user MFA | Was hours, manual, per tenant | Yes, read on every run |
| Confirming MFA is actually enforced at all | Hours per tenant, manual | No. Checklist in [MFA-Enforcement.md](MFA-Enforcement.md) |
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

If you changed `-ExcludeUpnPattern` between the two runs, expect `Filtered` rows. They are reported so the diff is complete, and they are deliberately left out of `LeftActionableBands`: a service account you regexed out of the report is not a user the campaign reached.

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

### 3b. Target the rollout

Two files are written on every run, and they answer different questions:

| File | Use it for |
|---|---|
| `<stem>_NoPasskey_Nonprivileged.csv` | Sizing the actionable rollout. Known, enabled, in-scope nonprivileged users without a registered passkey — not everyone without one: unknown registration status, privileged users and pattern-excluded users are outside it and counted separately. |
| `<stem>_SmsVoiceUsers_NoPasskey.csv` | Building the first campaign group. The subset who also hold a phone method. |

The second is a strict subset of the first. Quoting the SMS/voice number as "users without passkeys" understates the work, sometimes badly.

Two readings to avoid in a client conversation, because both are wrong and both are easy:

- **It is registration, not usage.** A name on these files means a method is registered against the account. It does not mean the person used it last week. Nothing in this tool reads sign-in method. If a client asks "how many are actually using SMS", the honest answer is that these files do not say and the sign-in logs do.
- **Neither is a lockout list.** Check `OtherSurvivingMfaMethods`. Blank there, beside a phone method, is the same population as `BlockedAtRetirement`. Anything listed means the user is safe on the date and still needs a passkey.

**Both files are nonprivileged users only.** Directory-role holders are omitted and counted separately, because they are a hand-worked track. Say this plainly to a client, because the natural reading is the wrong one: omission is deferral, not safety — a privileged account without a passkey is the most exposed row in the tenant. Work those from the assessment CSV, filtering on `PrivilegeSource`.

Detection covers directory roles held directly or through a group, active or PIM-eligible, and PIM for Groups eligibility (member or owner) on any group holding a role. Standing owners of a group that holds a role are held back too, as a conservative campaign exclusion rather than a role (`PrivilegeSource` = `RoleHoldingGroupOwner`); owners of unrelated groups are not. Sign in as **Global Reader**: Security Reader is refused the PIM for Groups read on role-assignable groups, and a refused read withholds the lists rather than guessing. Azure RBAC and app roles are outside the definition.

**If the privilege read fails, no targeting list is produced at all** — the assessment, action list and report still are. The console names the failing read and the consent to grant (`RoleManagement.Read.Directory` or `PrivilegedEligibilitySchedule.Read.AzureADGroup`) or the role to sign in with. Do not work around it by reading an earlier export: the tool deletes a stale one for exactly that reason. Get the consent, re-run.

The work after the file is manual and stays manual: review it, create the security group, add the members, confirm passkeys are enabled and the users are inside that policy's scope, then configure the registration campaign. This tool writes nothing to a tenant.

For an estate, rank on the sweep summary's `NoPasskeyNonprivileged` and `CampaignCandidates`, and check `PrivilegeDiscoveryComplete` before trusting either — a tenant whose detection failed shows blank, not zero.

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

Users enabled for SMS or voice through legacy per-user MFA service settings are in scope for the retirement, and the modern authentication methods policy says nothing about them. This used to be a manual check per tenant. Every run now reads it:

```powershell
.\Invoke-EntraSmsVoiceSweep.ps1 -TenantListPath .\tenants.csv `
    -ReportRoot "D:\ClientEvidence\EntraMigration\$stamp" `
    -ClientId <app-id> -CertificateThumbprint <thumbprint> `
    -ThrottleLimit 6
```

It needs no permission beyond the `Policy.Read.All` every run already uses, and costs one batched Graph call per twenty users. It is off by default only because it reads a beta endpoint — the state has no v1.0 equivalent.

**Set it on the baseline sweep at minimum.** Without it a tenant still running on legacy per-user MFA assesses as unremarkable: its exposed users land in `Moderate` with an instruction to go and check a portal, which across ninety tenants is ninety manual checks that do not happen.

Three numbers in the summary:

| Field | Read it as |
|---|---|
| `LegacyPerUserMfaChecked` | False means the tenant has an unassessed exposure, whatever else the report says. |
| `LegacyPerUserMfaInForce` | Users `enabled` or `enforced` there. These are in scope for the retirement regardless of the modern policy, **and the registration campaign will not reach them** until they are converted to it. |
| `LegacyPerUserMfaUnreadable` | Graph would not answer. Marked `(unreadable)`, never assumed clean. Anything above zero means re-run before calling the tenant assessed. |

A non-zero `LegacyPerUserMfaInForce` is not just a migration finding, it is an MFA enforcement finding: per-user MFA sitting underneath a Conditional Access policy is its own problem. See [MFA-Enforcement.md](MFA-Enforcement.md).

Do not report a zero-candidate tenant as finished until this has been read and come back clean.

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
4. **Nothing else, yet.** Group creation and campaign configuration are writes into customer tenants. Automating those is a different risk conversation from automating a read, and it should be a deliberate decision rather than a natural next step.

---

## Suggested improvements to the tool

Gaps worth knowing about, roughly in order of how much time each would save an estate-scale operator.

| Idea | Why it would help |
|---|---|
| Estate-wide HTML report | Reports are per-tenant today. A single roll-up ranking customers by Critical count is what an account manager actually wants. |
| Trend series rather than pairwise diff | The diff compares two runs. Ten runs plotted would show whether a campaign is decelerating, which is the thing you want to catch early. |
| Evaluating Conditional Access per user | Policies that require MFA are already inventoried by name and state, and so are the ones granting through an authentication strength that still allows SMS or voice. What is not answered is whether a given user is actually covered: that means modeling grant-control combinations, exclusion groups, and workload identities. It is the largest remaining gap and it is not a small feature. Manual checklist in [MFA-Enforcement.md](MFA-Enforcement.md) until then. |

---

## Related

- [README](../README.md) — installation, parameters, output schema
- [MFA-Enforcement.md](MFA-Enforcement.md) — why a Conditional Access policy is not the same as MFA being enforced
- [Risk-Classification.md](Risk-Classification.md) — how the five bands are derived, and the control-framework mapping
- [Microsoft-Migration-Background.md](Microsoft-Migration-Background.md) — Microsoft's timeline, and where SMS and voice can hide in a tenant
- [SECURITY.md](../SECURITY.md) — handling exports
