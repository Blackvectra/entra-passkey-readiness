# Security Policy

## What this tool does and does not do

`Get-EntraSmsVoiceMigrationImpact.ps1` performs **HTTP GET requests only** against Microsoft Graph. It does not create, update, or delete any object. It does not modify users, groups, authentication methods, the Authentication Methods Policy, the registration campaign, or any other tenant setting.

The only artefact it writes is a CSV file at the path you specify.

Every Graph endpoint the script contacts is declared against a single `$script:GraphBase` constant, so the network surface is auditable by reading the script. If you are running this in a client tenant for the first time, read it before you run it. That is the intended workflow.

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
| Every Graph call is HTTP GET | `Invoke-GraphGet` is the only request function | No create, update, or delete path exists. `grep` for `New-Mg`, `Set-Mg`, `Remove-Mg`, or a non-GET method returns nothing. |
| CSV formula injection guard | `Protect-CsvInjection`, applied at `Export-AssessmentCsv` | A display name of `=cmd\|'/c calc'!A1` or `=HYPERLINK(...)` executes when the report is opened in Excel and can exfiltrate adjacent rows. Display names are attacker-influenceable in tenants permitting self-service profile edits or B2B invites, and this report is specifically a file a manager opens in Excel. |
| HTML output encoding | `ConvertTo-SafeHtml`, applied to every interpolated value | Same untrusted-input problem, different sink. An unencoded display name containing markup is stored XSS in the browser of whoever you emailed the report to. |
| Content Security Policy on the report | `<meta http-equiv="Content-Security-Policy">` | Defence in depth. Even with an encoding bug, nothing can execute or make an outbound request. `referrer` is also suppressed. |
| Output ACL restriction | `Protect-OutputFile`, on by default on Windows | Files otherwise inherit the parent directory ACL. On a shared reports folder that can mean everyone reads your list of weak privileged accounts. Restricted to the file owner and local Administrators. Disable with `-SkipAclHardening` only if the filesystem rejects ACL changes. |
| Path traversal guard | `Invoke-EntraSmsVoiceSweep.ps1` label sanitisation | Tenant list CSVs are often generated from a PSA export, so labels are untrusted. Path characters are replaced, leading and trailing dots stripped, and only the leaf retained, so a label cannot write outside `-ReportRoot`. |
| URI escaping on identifiers | `Get-GroupDisplayName` | Values come from Graph, but a URI is never built from an unescaped identifier regardless of how trustworthy the source looks today. |
| Certificate-only app auth | `AppOnly` parameter set | Client secrets are unsupported. A secret that reads identity posture across an entire customer estate should not exist as a script parameter. |
| Tenant mismatch abort | `Connect-AssessmentGraph` | If `-TenantId` is a GUID and the established context does not match, the run stops rather than writing one customer's data into another customer's file. |
| Single export choke point | `Export-AssessmentCsv` | Injection guard and ACL hardening cannot be forgotten on a future export because there is only one place a CSV is written. |

## Least privilege

The script requests four delegated, read-only Graph scopes:

`Policy.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`

Recommended Entra role for the operator: **Global Reader** or **Security Reader**. Do not run this as Global Administrator. There is no capability in the script that requires it, and doing so needlessly places a privileged session on the workstation performing the assessment.

The script deliberately does not read legacy per-user MFA state, because doing so would require beta endpoints and broader scopes. That limitation is documented rather than engineered around.

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
