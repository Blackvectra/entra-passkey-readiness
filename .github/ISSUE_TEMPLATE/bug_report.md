---
name: Bug report
about: Something the assessment got wrong, or a run that failed
title: ''
labels: bug
---

<!--
STOP: do not paste live tenant output into this issue.

Exports from this tool name privileged accounts and state which of them lack a
phishing-resistant method. That is a targeting list. Redact UPNs and tenant IDs, or
reproduce the problem against the fictional data in examples/.
-->

## What happened

## What you expected instead

## How to reproduce

Command you ran, with identifiers redacted:

```powershell

```

## Environment

| | |
|---|---|
| `$PSVersionTable.PSVersion` | |
| `Microsoft.Graph.Authentication` version | |
| OS | |
| Auth mode | delegated / app-only certificate |
| Entra role of the signed-in account | |

## Error output

<!-- Re-run with -Verbose if the failure is a Graph call. Redact before pasting. -->

```

```

## Scale, if it is relevant

<!-- Throttling and pagination problems depend on size. Rough numbers are fine. -->

- Enabled users in the tenant:
- Groups targeted by the SMS or voice method:
