# Security Policy

## What this tool does and does not do

`Get-EntraSmsVoiceMigrationImpact.ps1` only **reads** from Microsoft Graph: every request is an HTTP GET, apart from the `POST /$batch` envelope that JSON batching requires, which carries nothing but GET requests. It does not create, update, or delete any object. It does not modify users, groups, authentication methods, the Authentication Methods Policy, the registration campaign, or any other tenant setting.

Every run writes two spreadsheets: the full assessment CSV at the path you specify, and an action list CSV beside it. `-HtmlReport`, `-ExportTickets`, and `-ExportFixScript` add further files in the same folder. All of them are written locally. Nothing is uploaded anywhere.

The generated remediation script is the one output that contains write commands. It is written to disk for you to read and run yourself; this tool never executes it.

Every Graph endpoint the script contacts is declared against a single `$script:GraphBase` constant, so the network surface is auditable by reading the script. If you are running this in a client tenant for the first time, read it before you run it. That is the intended workflow.

## Data sensitivity

**This tool processes identity-security metadata.** The output is not a benign user list.

A generated CSV contains, per user:

- User principal names and display names
- Object IDs
- Administrative status (`IsAdmin`)
- Every registered authentication method
- Whether the user is passwordless-capable
- The method their sign-in prompt defaults to today
- Legacy per-user MFA state
- Days since their last successful sign-in
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

These are implemented, not aspirational. Verify them by reading the script. **Proven by** names the test that fails if the control breaks; **Not tested** means the claim rests on reading the code alone, and is a gap to close.

| Control | Where | Why | Proven by |
|---|---|---|---|
| Every Graph call is a read | `Invoke-GraphGet`, plus `Invoke-GraphBatch` for the legacy per-user MFA read | No create, update, or delete path exists. The one non-GET verb is the `POST /$batch` envelope JSON batching requires, and every request inside it is a GET. No Graph SDK write cmdlet (`New-Mg`, `Update-Mg`, `Remove-Mg`, ...) is called, and every request's method is a literal, never a variable. | `tests/ReadOnlyGraph.Tests.ps1` |
| CSV formula injection guard | `Protect-CsvInjection`, applied at `Export-AssessmentCsv` | A display name of `=cmd\|'/c calc'!A1` or `=HYPERLINK(...)` executes when the report is opened in Excel and can exfiltrate adjacent rows. Display names are attacker-influenceable in tenants permitting self-service profile edits or B2B invites, and this report is specifically a file a manager opens in Excel. | `tests/Sanitization.Tests.ps1` |
| HTML output encoding | `ConvertTo-SafeHtml`, applied to every interpolated value | Same untrusted-input problem, different sink. An unencoded display name containing markup is stored XSS in the browser of whoever you emailed the report to. | `tests/Sanitization.Tests.ps1`, `tests/HtmlReport.Tests.ps1` |
| Content Security Policy on the report | `<meta http-equiv="Content-Security-Policy">` | Defense in depth. Even with an encoding bug, nothing can execute or make an outbound request. `referrer` is also suppressed. | Not tested |
| Output permission restriction | `Protect-OutputFile`, on by default on every platform | A new file otherwise takes its permissions from where it lands. On Windows that means inheriting the parent directory ACL, which on a shared reports folder can mean everyone reads your list of weak privileged accounts; on Linux and macOS it means whatever the umask allows, which on most distributions leaves it world-readable. Windows files are restricted to the owner and local Administrators; Linux and macOS files are set to `0600`, directories to `0700`. Disable with `-SkipAclHardening` only where the filesystem rejects permission changes. | `tests/OutputHardening.Tests.ps1` |
| Parallel handoff isolation | `Invoke-EntraSmsVoiceSweep.ps1` | A concurrent sweep hands each child process its parameters through a directory in the shared temp location. It holds no user rows, but it names every customer being assessed, where their evidence is being written, and which app registration is reading their tenant. The directory has a random name and is created new, never adopted: an earlier build named it from the start time and reused an existing directory of that name, so a local user who pre-created it received every child's parameters and could repoint the operator's certificate at another tenant. It is created with `mkdtemp` semantics, owner-only (`0700`) from the first instant, whatever `-SkipAclHardening` says, and removed when the sweep ends. | `tests/HandoffDirectory.Tests.ps1` |
| Path traversal guard | `Invoke-EntraSmsVoiceSweep.ps1` label sanitization | Tenant list CSVs are often generated from a PSA export, so labels are untrusted. Path characters are replaced, leading and trailing dots stripped, and only the leaf retained, so a label cannot write outside `-ReportRoot`. | `tests/OutputNaming.Tests.ps1`, `tests/SweepGui.Tests.ps1` |
| URI escaping on identifiers | `Get-GroupDisplayName` | Values come from Graph, but a URI is never built from an unescaped identifier regardless of how trustworthy the source looks today. | Not tested |
| Certificate-only app auth | `AppOnly` parameter set | Client secrets are unsupported. A secret that reads identity posture across an entire customer estate should not exist as a script parameter. | Not tested |
| Tenant mismatch abort | `Connect-AssessmentGraph` | If `-TenantId` is a GUID and the established context does not match, the run stops rather than writing one customer's data into another customer's file. | Not tested |
| Single export choke point | `Export-AssessmentCsv` | Injection guard and ACL hardening cannot be forgotten on a future export because there is only one place a CSV is written. | Not tested |
| Inert text in the remediation script | `ConvertTo-InertScriptText` inside `New-RemediationScript` | The generated script is the one output you are told to edit and run, with write permissions, and it carries display names, UPNs and ids from the tenant plus the customer label from a PSA export. Every such value has control characters and Unicode line separators flattened and `#>` broken up, so it cannot end the comment it sits in. User ids are also escaped with PowerShell's own single-quote escaper, which covers curly quotes, so uncommenting a Graph line runs only that Graph call. | `tests/RemediationScript.Tests.ps1` |

## Least privilege

The script requests four delegated, read-only Graph scopes:

`Policy.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`

Recommended Entra role for the operator: **Global Reader** or **Security Reader**. Do not run this as Global Administrator. There is no capability in the script that requires it, and doing so needlessly places a privileged session on the workstation performing the assessment.

Legacy per-user MFA state is read on every run. It is the one value that comes from a beta Graph endpoint, and it needs no permission beyond the `Policy.Read.All` already listed above. `-SkipLegacyPerUserMfa` opts out of the beta surface entirely, at the cost of leaving that exposure unmeasured.

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
