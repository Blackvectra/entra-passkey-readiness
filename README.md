# entra-passkey-readiness

Read-only PowerShell assessment that identifies which Microsoft Entra ID users are exposed to the retirement of Microsoft-provided SMS and voice authentication, and which are ready for passkeys.

The script answers a question the Entra portal does not answer directly: **which specific users are both targeted by the SMS/voice Authentication Methods Policy and unable to satisfy MFA without it after the retirement date.**

It performs GET requests only. It does not modify users, groups, policies, authentication methods, or registration campaigns.

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
    -CustomerName "Contoso Manufacturing" -HtmlReport -ExportRemediationGroup
```

`-HtmlReport` writes a self-contained HTML file beside the CSV. No CDN, no external assets, no JavaScript, so it survives being emailed, archived, or opened offline years later. It leads with a live countdown to both deadlines, shows the risk bands, prints the resolved policy scope with group names, and tables only the Critical, High, and Moderate findings so the accounts that matter are not buried under the ones that do not.

All user-supplied strings are HTML-encoded before rendering. Directory display names are attacker-influenceable in tenants that permit self-service profile edits or B2B invites, and an unencoded display name containing markup would execute in the browser of whoever you emailed the report to.

See [examples/Example-Report.html](examples/Example-Report.html) for a rendered sample built entirely from fictional data.

`-ExportRemediationGroup` writes a second CSV containing just the Critical, High, and Moderate users. That is the membership list for the migration security group Microsoft's guidance tells you to create as step one, ready for bulk import. Producing the list is read-only; creating and populating the group stays a deliberate manual action, because that is a write and this tool does not write.

### Ticket queue for your PSA

```powershell
.\Get-EntraSmsVoiceMigrationImpact.ps1 -TenantId contoso.onmicrosoft.com `
    -CustomerName "Contoso Manufacturing" -ExportTickets -ExportRemediationGroup -HtmlReport
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

Each `Description` is self-contained: the user, their registered methods, why the ticket exists, and numbered remediation steps. A tech can work it without opening the report. Every remediation sequence registers the new method before removing the phone method, because doing it in the other order creates the lockout you are trying to prevent.

Due dates target 2026-09-01 while that date is still ahead, then fall back to 2027-02-01.

See [examples/Example-Tickets.csv](examples/Example-Tickets.csv) for a sample built from fictional data. Test your import mapping against it before running against a real tenant.

**Note on multiline descriptions.** Ticket bodies contain embedded newlines inside quoted CSV fields. This is valid RFC 4180 and handled by every PSA tested, but some older importers reject it. Check against the sample first.

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-TenantId` | string | current Graph context | Tenant GUID or verified domain. Forces re-auth if it does not match the live session. Mandatory for app-only. |
| `-ClientId` | guid | none | App registration ID for unattended app-only auth. Requires `-CertificateThumbprint`. |
| `-CertificateThumbprint` | string | none | Certificate thumbprint for app-only auth. |
| `-OutputPath` | string | timestamped CSV beside the script | Destination CSV path. Parent directory is created if missing. |
| `-IncludeUnaffected` | switch | off | Include every enabled user, not just migration candidates. |
| `-HtmlReport` | switch | off | Also write a self-contained HTML report beside the CSV. |
| `-CustomerName` | string | none | Heading used on the HTML report. |
| `-ExportRemediationGroup` | switch | off | Write a UPN list of Critical/High/Moderate users for bulk group import. |
| `-ExportTickets` | switch | off | Write a PSA-importable ticket queue. |
| `-MaxIndividualTickets` | int | 50 | Cap on individual tickets before High findings batch into a campaign ticket. |
| `-SkipAclHardening` | switch | off | Skip restricting output file permissions. Use only where the filesystem rejects ACL changes. |
| `-PassThru` | switch | off | Emit per-user objects to the pipeline in addition to the summary. |

---

## Output

### Console summary

| Field | Meaning |
|---|---|
| `TenantId` | Tenant the assessment actually ran against |
| `RegistrationCampaignState` | `enabled`, `disabled`, or `default (Microsoft managed)` |
| `SmsPolicyState` / `VoicePolicyState` | AMP state of each method |
| `SmsPolicyInclude` / `SmsPolicyExclude` | Resolved include and exclude targets, with transitive member counts |
| `InSmsPolicyScope` / `InVoicePolicyScope` | Enabled users resolved into each method's scope |
| `MigrationCandidates` | Users in policy scope **or** with a phone method registered |
| `Critical` / `High` / `Moderate` / `Low` | Risk-band counts across migration candidates |
| `PasswordlessCapableInScope` | In-scope users who already have a surviving method |
| `UsersMissingFromReport` | Enabled users with no row in the registration report (see Limitations) |
| `OldestReportRowUtc` | Age of the oldest registration-report row; the honest confidence marker for the run |

### CSV fields

| Column | Type | Description |
|---|---|---|
| `Risk` | string | Critical, High, Moderate, Low, or Informational. See [docs/Risk-Classification.md](docs/Risk-Classification.md). |
| `Reason` | string | Plain-language justification for the risk band. |
| `DisplayName` | string | Directory display name. |
| `UserPrincipalName` | string | UPN. |
| `UserId` | guid | Object ID. |
| `UserType` | string | `Member` or `Guest`. |
| `IsAdmin` | bool | Reported by the registration report as holding a privileged role. |
| `InSmsPolicyScope` | bool | Resolved into the SMS method's AMP scope after exclusions. |
| `InVoicePolicyScope` | bool | Resolved into the voice method's AMP scope after exclusions. |
| `HasPhoneMethodRegistered` | bool | Has at least one phone-based method registered. |
| `PhoneMethodsRegistered` | string | Semicolon-delimited subset: `mobilePhone`, `alternateMobilePhone`, `officePhone`, `smsSignIn`. |
| `AllMethodsRegistered` | string | Every method reported for the user. |
| `IsPasswordlessCapable` | bool | Reports a passwordless method. This is the mitigating control. |
| `IsMfaCapable` | bool | Reports a method that can satisfy MFA today. |
| `IsMfaRegistered` | bool | Reports any registered MFA method. |
| `SystemPreferredMethods` | string | System-preferred MFA methods reported for the user. |
| `InRegistrationReport` | bool | False means the user had no row in the report; registration fields default to `False`. |
| `RegistrationReportLastUpdatedUtc` | datetime | When the report row was last refreshed. |

Rows are sorted highest risk first, then admins ahead of standard users, then display name.

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

---

## Coverage: who this actually finds

The claim is "every user in the tenant who is exposed." Here is exactly what that means, so you can defend it in a client conversation.

**Included.** Every enabled user object returned by `/users`, members and guests, with full pagination. Every user resolved into SMS or voice policy scope, including through nested groups, with exclusions applied afterwards as an override. Every user with a phone-based method in the registration report, whether or not they resolve into modern policy scope.

**A user cannot be silently missed on the registration side.** If a user has no row in the registration report, the registration-derived fields default to `False`, which means `IsPasswordlessCapable` is `False`, which means an in-scope user lands in `High` rather than being quietly dropped. The failure mode is a false positive, not a false negative. `InRegistrationReport` marks these rows and `UsersMissingFromReport` counts them so you can tell the difference.

**Pagination failures are not silent either.** A throttled request retries with backoff, and an unrecoverable one throws. There is no code path that returns a short list and reports it as complete.

**Not included, by design or by data source:**

| Population | Why | What to do |
|---|---|---|
| Disabled users | `userRegistrationDetails` does not return them | Re-run after any bulk re-enablement |
| Users enabled for SMS/voice only via legacy per-user MFA | Requires beta endpoints and broader scopes; would break the least-privilege model | The `Moderate` band surfaces the symptom. Validate that population in the legacy MFA settings portal. |
| Effective Conditional Access outcome | Not read | Policy scope is not the same as being challenged at sign-in |
| Non-human accounts | Shared mailboxes, sync accounts, and service accounts appear as ordinary users | Filter by your naming convention or exclude them from the remediation group after review |

That last one matters operationally. A tenant with `All users` targeting will surface shared mailbox and service account objects as migration candidates. They are technically in scope but nobody signs into them interactively, so review before they become tickets.

## Limitations

These are properties of the data sources, not defects. Read them before presenting results to a client.

- **Disabled users are excluded.** `userRegistrationDetails` does not return disabled users. The script reads `accountEnabled` separately and assesses enabled users only. Disabled accounts that get re-enabled after the assessment are not represented.
- **Reporting latency.** The registration report is not real-time. `RegistrationReportLastUpdatedUtc` is included per row and `OldestReportRowUtc` in the summary so the age of the evidence is visible. Do not treat a run as a live directory query.
- **SMS and voice are not separately registered.** Entra stores a phone number with a type, not an "SMS registration" and a "voice registration." `mobilePhone` can satisfy both; `officePhone` is voice-only. There is no clean per-user SMS-versus-voice split available, so the script reports phone-method capability and leaves policy scope to distinguish intent.
- **Legacy per-user MFA is not read.** Users enabled for SMS or voice through legacy per-user MFA service settings are also in scope for the retirement, but that state is not exposed through the read-only Graph v1.0 surface this script uses. Reading it requires beta endpoints and broader scopes, which would break the least-privilege model. `Moderate` findings are the signal that this exposure likely exists; validate them manually in the legacy MFA service settings portal.
- **Conditional Access is not evaluated.** A user may be in AMP scope but never actually challenged, or may be blocked by a Conditional Access grant this script does not read. Policy scope is not the same as effective sign-in behaviour.
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

---

## License

MIT. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Microsoft.
