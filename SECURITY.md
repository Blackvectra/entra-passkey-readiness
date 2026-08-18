# Security Policy

## What this tool does and does not do

`Get-EntraSmsVoiceMigrationImpact.ps1` performs **HTTP GET requests only** against Microsoft Graph. It does not create, update, or delete any object. It does not modify users, groups, authentication methods, the Authentication Methods Policy, the registration campaign, or any other tenant setting. The same holds for `Invoke-EntraSmsVoiceSweep.ps1`, which only runs it, and for `Compare-EntraSmsVoiceAssessment.ps1`, which reads two files and makes no Graph call at all.

The only artefact it writes is a CSV file at the path you specify.

Every Graph endpoint the assessment contacts is declared against two constants — `$script:GraphBase` for v1.0 and `$script:GraphBeta` for the single beta read described under [Least privilege](#least-privilege) — so the network surface is auditable by reading the script. If you are running this in a client tenant for the first time, read it before you run it. That is the intended workflow.

**`Set-EntraPasskeyOptOut.ps1` is the one exception in this repository, and it is deliberate.** It is the only write tool here: it PATCHes `optOutSettings.passkeyDynamicMigration` on the beta Authentication Methods Policy to defer the 2026-09-01 passkey auto-enablement. No assessment path invokes it. It is a separate script you run yourself, it takes a mandatory `-Direction OptOut|ClearOptOut` rather than inferring intent from an absent switch, it declares `ConfirmImpact = 'High'` so it prompts by default, it supports `-WhatIf`, and it needs `Policy.ReadWrite.AuthenticationMethod` as an application permission that the assessment neither requests nor requires. Opting out defers 2026-09-01 only; the 2027-02-01 retirement is not opt-outable.

## Data sensitivity

**This tool processes identity-security metadata.** The output is not a benign user list.

A generated CSV contains, per user:

- User principal names and display names
- Object IDs
- Administrative status (`IsAdmin`)
- Every registered authentication method
- Whether the user is MFA-capable, MFA-registered, and passwordless-capable
- System-preferred authentication methods
- A risk band that explicitly identifies which accounts are weakest

Taken together, this is a targeting list. It tells a reader exactly which privileged accounts rely on phone-based authentication and lack a phishing-resistant method. In the hands of an attacker running a SIM-swap or MFA-fatigue campaign (MITRE ATT&CK `T1451`, `T1621`, `T1111`), it removes the reconnaissance step entirely.

Handle it accordingly:

- **Never commit a real export to version control**, including a private repository. Private repositories change visibility, get forked, get transferred, and get accessed by collaborators who were never scoped to that client.
- Store exports in your protected client documentation system with the same controls you apply to a penetration test report.
- Apply a retention period. Stale identity posture data has no operational value and unbounded downside.
- Encrypt at rest and in transit when sharing with a client. Do not email the raw CSV.
- Redact or aggregate before putting findings in a slide deck, ticket, or chat message.

The repository `.gitignore` blocks the default output filename pattern, `*.tenant.csv`, and `/reports/`. **This is a safety net, not a control.** An export written to a path outside those patterns will not be caught.

## Controls built into the code

These are implemented, not aspirational. Verify them by reading the script.

| Control | Where | Why |
|---|---|---|
| Every Graph call in the assessment is HTTP GET | `Invoke-GraphGet` is the only request function in `Get-EntraSmsVoiceMigrationImpact.ps1` | No create, update, or delete path exists in the assessment, the sweep, or the compare script. The one write path in the repository lives in a separate file that none of them call. Verify it with the command below. |
| CSV formula injection guard | `Protect-CsvInjection`, applied at `Export-AssessmentCsv` | A display name of `=cmd\|'/c calc'!A1` or `=HYPERLINK(...)` executes when the report is opened in Excel and can exfiltrate adjacent rows. Display names are attacker-influenceable in tenants permitting self-service profile edits or B2B invites, and this report is specifically a file a manager opens in Excel. |
| HTML output encoding | `ConvertTo-SafeHtml`, applied to every interpolated value | Same untrusted-input problem, different sink. An unencoded display name containing markup is stored XSS in the browser of whoever you emailed the report to. |
| Content Security Policy on the report | `<meta http-equiv="Content-Security-Policy">` | Defence in depth. Even with an encoding bug, nothing can execute or make an outbound request. `referrer` is also suppressed. |
| Output ACL restriction | `Protect-OutputFile`, on by default on Windows | Files otherwise inherit the parent directory ACL. On a shared reports folder that can mean everyone reads your list of weak privileged accounts. Restricted to the file owner and local Administrators. Disable with `-SkipAclHardening` only if the filesystem rejects ACL changes. |
| Path traversal guard | `Invoke-EntraSmsVoiceSweep.ps1` label sanitisation | Tenant list CSVs are often generated from a PSA export, so labels are untrusted. Path characters are replaced, leading and trailing dots stripped, and only the leaf retained, so a label cannot write outside `-ReportRoot`. |
| URI escaping on identifiers | `Get-GroupDisplayName` | Values come from Graph, but a URI is never built from an unescaped identifier regardless of how trustworthy the source looks today. |
| Certificate-only app auth | `AppOnly` parameter set | Client secrets are unsupported. A secret that reads identity posture across an entire customer estate should not exist as a script parameter. |
| Tenant mismatch abort | `Connect-AssessmentGraph` | If `-TenantId` is a GUID and the established context does not match, the run stops rather than writing one customer's data into another customer's file. |
| Single export choke point | `Export-AssessmentCsv` | Injection guard and ACL hardening cannot be forgotten on a future assessment export because there is only one place the assessment writes a CSV. `Set-EntraPasskeyOptOut.ps1` writes its own `-ResultPath` record and applies the same injection guard inline; that file holds customer labels, tenant IDs, and opt-out state rather than per-user data. |

### Verifying the read-only claim yourself

Run this from the repository root. It is the whole audit, and it is worth running before you trust the first row of that table:

```powershell
Get-ChildItem -Recurse -Filter *.ps1 |
    Select-String -Pattern 'New-Mg', 'Set-Mg', 'Remove-Mg', 'Invoke-MgGraphRequest -Method (?!GET)' |
    Select-Object -ExpandProperty Filename -Unique
```

The expected result is exactly one line:

```
Set-EntraPasskeyOptOut.ps1
```

That file is the repository's only write tool and is expected in the output. It is not imported, dot-sourced, or shelled out to by `Get-EntraSmsVoiceMigrationImpact.ps1`, `Invoke-EntraSmsVoiceSweep.ps1`, or `Compare-EntraSmsVoiceAssessment.ps1`, so nothing you run as an assessment can reach it. **Any other filename in that output is a defect**, and is worth a security advisory rather than an issue.

## Least privilege

The script requests four delegated, read-only Graph scopes:

`Policy.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`

Recommended Entra role for the operator: **Global Reader** or **Security Reader**. Do not run this as Global Administrator. There is no capability in the script that requires it, and doing so needlessly places a privileged session on the workstation performing the assessment.

The assessment makes **exactly one call against a beta endpoint**: a GET on `beta/policies/authenticationMethodsPolicy`, in `Get-AuthMethodsPolicyState`. It exists because `optOutSettings.passkeyDynamicMigration` — whether this tenant has been deferred past the 2026-09-01 auto-enablement — is not exposed on the v1.0 surface, so there is no v1.0 request that answers the question. It is still a GET, it needs no scope beyond the `Policy.Read.All` already listed, and a failure is non-fatal: the tenant reports `PasskeyOptedOut = read-failed` rather than being recorded as a tenant that was never deferred.

The assessment still deliberately does not read legacy per-user MFA state. That would need broader scopes, not just a beta endpoint, and the limitation is documented rather than engineered around: `AssessmentConfidence = LowerBound` marks the tenants where it changes what the numbers mean.

`Set-EntraPasskeyOptOut.ps1` sits outside this model on purpose. It requires `Policy.ReadWrite.AuthenticationMethod` as an **application** permission, and certificate-based app-only authentication. Consent to it separately from the assessment app — ideally in a separate app registration — so a read-only estate sweep never carries a permission that can rewrite an authentication policy.

## Credentials

The script never handles, stores, or logs credentials. Authentication is delegated entirely to `Connect-MgGraph` and the Microsoft identity platform. No secrets, tokens, certificates, or client IDs are read from or written to disk by this script.

If you adapt it for app-only authentication, do not commit the certificate thumbprint, client ID, or tenant ID. Source them from environment variables or a secret store.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a vulnerability

If you find a security issue in this script, particularly anything that could cause an unintended write to a tenant, an unintended broadening of requested scopes, or leakage of tenant data:

Open a **private security advisory** through the repository's Security tab rather than a public issue. Include the script version, PowerShell version, `Microsoft.Graph.Authentication` module version, and reproduction steps.

Please do not include real tenant data, UPNs, tenant IDs, or tokens in a report. Redact or synthesise.

Expect an initial response within seven days.

## Third-party dependencies

One: `Microsoft.Graph.Authentication`, published by Microsoft. Keep it current. Verify the publisher when installing from a machine that has non-default PSRepository entries registered.
