# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **The assessment crashed on any tenant with an enabled user outside both SMS and voice policy scope**, which is effectively every real tenant. Trimming the CSV schema removed `HasPhoneMethodRegistered`, but the candidate filter still read it off each row, and under `Set-StrictMode -Version Latest` that throws. It reached review and merge because `-or` short-circuits: the bad access is only evaluated for a user in neither scope, so a fixture where everyone is in scope never touches it. That was exactly the end-to-end fixture, where SMS targeted `all_users`. The filter now reads `PhoneMethodsRegistered`, and the fixture scopes SMS to a group so out-of-scope users — the Moderate and Informational populations — are exercised on every run. Reintroducing the bug now fails 13 of 14 end-to-end assertions; before, it passed all 12.

### Added
- **`-ExcludeUpnPattern`**, on both the assessment and the sweep. Regular expressions matched case-insensitively against the UPN, for the shared mailboxes, sync accounts, and service accounts that a tenant targeting `All users` surfaces as migration candidates. Nobody signs into them interactively, so ticketing them wastes an afternoon, and the naming convention that identifies them is local to an estate rather than guessable — which is why it is a parameter and not a built-in list.

  Matching users are **marked, not deleted**: the row stays in the assessment CSV with `Risk = Excluded`, and they are absent from every count, the action list, the tickets, and the report. A filter that silently removes people from a security assessment is how a real account disappears behind a careless pattern, with nothing about the output looking unusual. `UsersExcludedByPattern` and the patterns used are reported in the summary and on the console, so the number can be sanity-checked on a first run.

  An invalid regular expression, or an empty pattern in the middle of a list — which would match every user in the tenant — is rejected at parameter binding, before any tenant is contacted.


### Breaking
- **The assessment CSV is trimmed from twenty columns to fourteen.** `IsMfaCapable`, `IsMfaRegistered`, `SystemPreferredMethods`, `HasPhoneMethodRegistered`, `InRegistrationReport`, and `RegistrationReportLastUpdatedUtc` are gone: none of them changed what anybody did with the file, and the width made it awkward to read in Excel. Evidence age is still reported once as `OldestReportRowUtc` in the summary, and a user with no registration-report row now says so in `AllMethodsRegistered` rather than needing a boolean column, so that distinction is not lost. `OnlyPhoneBasedMfa` is renamed `BlockedAtRetirement` to match the action list, and moves up to fourth so the lockout flag is visible without scrolling. Every column `Compare-EntraSmsVoiceAssessment.ps1` matches on is retained, and a test now asserts that so a future trim cannot silently break the diff a month later.
- **A run now produces two spreadsheets and nothing else**: the full assessment CSV and the action list CSV. Both open straight into Excel. The HTML client report moves behind `-HtmlReport` and is off by default — it is for handing a client something directly, not for the normal run, where what gets attached to a ticket and worked from is a spreadsheet. `-ExportRemediationGroup` is gone, since the action list it produced is now written every time. `Invoke-EntraSmsVoiceSweep.ps1` mirrors all of this and now always passes `-CustomerName`, so per-tenant output is client-labelled without hand-editing.
- `-CustomerName` is folded into the output filenames as well as the report heading. Running several clients back to back previously produced sets of files distinguishable only by timestamp, which is a poor thing to be untangling at the point you are attaching one set to a ticket. The tool stem stays at the front of the filename because the `.gitignore` rule that stops a live export being committed anchors on it. The label is sanitised before it reaches a path.
- The action list file is named `..._ActionList.csv` rather than `..._RemediationGroup.csv`, and the sample is `examples/Example-ActionList.csv`. It does the same two jobs; the name now matches the one people use it for. `.gitignore` covers both names.

### Fixed
- **A user missing from the registration report crashed the whole run.** `$methods = if ($registration) { ... } else { @() }` yields `$null` rather than an empty array, because PowerShell unrolls an empty collection on the way out of an expression. Every user with no report row went down that branch, so the first one encountered killed the assessment after every Graph call had already been paid for. Recently created accounts and ordinary reporting latency both produce that state, and the README describes it as expected, so this would have fired on real tenants. Fixed at the source, and `Test-OnlyPhoneBasedMfa` now accepts null as the ordinary case it is.
- **The summary read a column that had been trimmed from the row.** `OldestReportRowUtc` was derived from a per-row `RegistrationReportLastUpdatedUtc` that no longer existed, which under `Set-StrictMode -Version Latest` throws. It now reads the timestamps from the Graph payloads directly.
- **Ticket duplication on re-runs.** `-ExportTickets` regenerated the full queue every time with no memory of what was imported last month, so a second import raised a duplicate ticket for every user who had not remediated. A run now records which users it ticketed, and a later run raises a ticket only for a user who is new or whose risk band got worse — somebody who was High last month and is High today is already in a queue, and a second ticket is noise a technician has to close. Verified across four runs: 6 tickets, then 0, then 2 for exactly the one worsened and one new user, then the full queue again under `-IgnoreTicketHistory`.

  The history defaults to a file beside the ticket CSV and can be redirected with `-TicketHistoryPath`, which matters because dated output folders would otherwise make every run look like a first run; the sweep keeps history per tenant folder rather than per dated run for that reason. The file holds object IDs and risk bands only — no names, no UPNs. A corrupt history warns and behaves as a first run rather than failing the assessment, because duplicate tickets are recoverable and a lost assessment is not. `TicketsSuppressedAsAlreadyRaised` in the summary distinguishes "already ticketed" from "found nothing".

### Added
- **`BlockedAtRetirement`: the count of users who are stopped at sign-in on 2027-02-01.** Per Microsoft Learn, the blocking registration prompt applies to users whose *only available MFA method is SMS or voice*. That is narrower than the risk bands, which measure whether a user holds a passwordless method: somebody with Microsoft Authenticator push is `High` and is not stopped, because Authenticator is not being retired. The two populations cut across each other, so a `Moderate` user can be stopped while a `High` user is not, and sorting work by risk band alone leaves people locked out. Surfaced as an `OnlyPhoneBasedMfa` column per user, `BlockedAtRetirement` and `BlockedAdminsAtRetirement` in the summary, its own band at the top of the HTML report, a red console line, and the first sort key inside each band of the action list. A method the tool does not recognise counts as not surviving, so an unfamiliar name makes a user read as more exposed rather than less, and the names are surfaced in `UnrecognisedMethods` so the list can be maintained. `email`, `securityQuestion`, and `temporaryAccessPass` deliberately do not count: the first two satisfy self-service password reset rather than MFA, and the third expires by design.
- `-ExportRemediationGroup` now writes an action list you can attach to a ticket you raised yourself, not just a bare membership list. Columns are `Risk`, `DisplayName`, `UserPrincipalName`, `IsAdmin`, `PhoneMethodsRegistered`, `IsPasswordlessCapable`, `NextStep`, `UserId` — everything a technician needs and none of the diagnostic columns that make the full export wide — sorted worst first with admins ahead of standard users so it is worked top-down. It still bulk-imports as a group membership list on `UserPrincipalName`. Teams that raise their own tickets can now skip `-ExportTickets` entirely. Extracted to a `New-ActionList` function so the published sample is generated by the same path a real run takes rather than by something that resembles it.
- `examples/Example-ActionList.csv`, and `tests/Samples.Tests.ps1` checking the published samples against each other: that the action list reproduces exactly from the assessment rows, that a user's next step is identical in the CSV, the action list, and their ticket, that Critical users are never batched, and that no sample carries a non-fictional domain.
- Per-user remediation guidance in every deliverable. A new `NextStep` column in the assessment CSV, a next step under each row in the HTML report, and a `Next step` line opening each individual ticket description. Previously the mitigation steps existed only inside the ticket export, so anyone running without `-ExportTickets`, or handing over the CSV rather than importing to a PSA, got the list of affected users without the actions. All three come from one `Get-RemediationStep` function, so the guidance cannot drift between the report a client reads and the ticket a technician works. The step names the user's actual registered methods rather than saying "the phone method", and a test enforces across every band that no instruction removes a phone method before its replacement is registered.

- `Compare-EntraSmsVoiceAssessment.ps1`: diffs two assessment exports and reports per-user movement between them — who improved, who regressed, who appeared, who left the candidate set. The first run of an assessment answers "who is exposed"; every run after it answers "did the campaign move anybody", and that question is unreadable from a 400-row CSV where 380 rows are identical to last month's. Reads files only, makes no Graph calls, needs no permissions. Users are matched on object ID so a rename does not read as a new account, with the fallback recorded in a `MatchedOn` column.
- `Invoke-EntraSmsVoiceSweep.ps1 -ThrottleLimit`: assess up to 16 tenants concurrently. Each tenant runs in its own pwsh process rather than a runspace, because `Microsoft.Graph.Authentication` holds the signed-in context in process-wide state and concurrent connections inside one process could serve one customer's token to another customer's report. Requires app-only authentication; interactive sign-in cannot be driven concurrently.
- `Invoke-EntraSmsVoiceSweep.ps1 -Resume`: skip tenants that already succeeded in the most recent sweep summary under `-ReportRoot`, for picking up an estate-wide run that died partway through. Rows for skipped tenants are carried into the new summary rather than dropped, so the summary always describes the whole tenant list and a second resume does not re-assess what the first one finished.
- Pester suite covering the risk model, AMP include/exclude resolution against a mocked Graph, and both output-sanitization controls. Tests lift function definitions out of the script by AST rather than dot-sourcing it, so they exercise the real code without a refactor whose only purpose is testability.
- `tests/RepoHygiene.Tests.ps1`: fails the build on broken relative documentation links, `.gitignore` negations that no longer match where a file lives, unresolvable `docs/` references in script comments, and anything export-shaped committed outside `examples/`. This is the class of defect that shipped in 1.0.0 and was invisible to review.
- `docs/Operations-Playbook.md`: how to run the assessment across an estate. Covers where the time actually goes (app-only consent, not the assessment), one-time setup, the recurring sweep-diff-act-report loop, a cadence worked backwards from the two Microsoft dates, and the known friction — ticket duplication on re-runs, service accounts surfacing under `All users` targeting, the manual legacy per-user MFA check, and reporting latency.
- `tests/EndToEnd.Tests.ps1`: runs the real script, unmodified, against a stubbed `Microsoft.Graph.Authentication` module placed on `PSModulePath`, in a child process so the stub cannot leak into the test session. Everything after the function definitions — the row loop, the summary, the exports — only executes on a real run, so unit tests never touched it, and both of the crashes fixed above lived there. Covers the output file set, the CSV schema, exclusion of disabled users, the user with no report row, the blocked-versus-High distinction, and ticket history containing no identifying data.
- GitHub Actions CI running PSScriptAnalyzer and Pester on every push and pull request, with analyzer findings annotated onto the diff.
- `PSScriptAnalyzerSettings.psd1`, `CONTRIBUTING.md`, a pull request template, and issue templates for bugs and feature requests. Two analyzer rules are excluded with the reasoning written out rather than suppressed inline.

### Fixed
- Repository layout now matches every path referenced in the project. Docs moved to `docs/`, samples to `examples/`. Previously all files sat at the repository root, which made the seven `docs/` and `examples/` links in `README.md` dead, left the script's help-text reference to `docs/Microsoft-Migration-Background.md` pointing at nothing, and stopped the `!examples/...` negations in `.gitignore` from applying — most consequentially, `tenants.sample.csv` at the root was matched by the `tenants.*.csv` rule with no negation to rescue it.
- Removed the `2027-01-28` line from the assessment's console timeline. That date is not published in Microsoft Learn, in either the retirement article or the FAQ, and the script was printing it as a customer-managed telecom provider configuration deadline. Learn gives `2026-10-30` as the date provider configuration first becomes possible and `2027-02-01` as the date by which it must be in place; the timeline now prints those.

### Changed
- `README.md` restructured. Status badges, a quick start that gets to a working command in the first screen, a table of the three scripts and what each is for, and a contents list. The quick start previously sat below roughly ninety lines of background, so the first thing a reader met was the Microsoft timeline rather than how to run the tool. Adds sections for concurrent sweeps, resuming an interrupted sweep, tracking progress between runs, and development; parameter tables now cover all three scripts.
- HTML report redesigned as a light, print-first client deliverable. It was a dark dashboard, which reads as a screenshot rather than a report and costs a reader half a toner cartridge. Adds a generated executive summary in prose, so the reader is not left to interpret six numbers themselves; a proportional risk bar; findings split into one table per band, because a technician works Critical to completion before touching High; and a scope-and-method section stating plainly what was and was not assessed. The print stylesheet repeats table headers across pages, keeps bands and cards off page breaks, and sets page margins, so printing to PDF produces a deliverable rather than a screenshot. Still self-contained: no JavaScript, no external requests, same locked-down content security policy.
- Executive summary counts distinct users in policy scope. Adding `InSmsPolicyScope` to `InVoicePolicyScope` double-counts anyone targeted by both methods, which can report more users in scope than the tenant has users.
- `examples/Example-Report.html` regenerated, and its figures now match the ten rows in `examples/Example-MigrationImpact.csv` exactly. The previous sample paired a 10-row table with summary figures describing a 412-user tenant.
- `README.md` "date discrepancy" note rewritten. It previously attributed the `Jan 28, 2027` date to Microsoft Learn while describing it as a Security Store deadline. It now states that Learn does not use the date at all and frames it as an artefact of Microsoft's analyzer output.
- `README.md` risk-band summary for Moderate now includes the "no passwordless method" condition, matching `Get-RiskAssessment` and `docs/Risk-Classification.md`.
- `README.md` ticketing table now states that `-MaxIndividualTickets` is a combined budget across Critical and High individual tickets, which is what the code does, rather than a High-only cap.
- Added the Choose Your Own Telephony Provider article to `README.md` references.
- `Invoke-EntraSmsVoiceSweep.ps1` now actually guards the per-tenant `Disconnect-MgGraph` call with its `Get-Command` check. The check ran and discarded its result, so it guarded nothing.

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
