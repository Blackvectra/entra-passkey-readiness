---
name: Feature request
about: Something the assessment should do that it does not
title: ''
labels: enhancement
---

## The problem

<!-- What are you unable to answer or do today? Describe the situation, not the
     solution you have in mind — the situation is the part that is hard to guess. -->

## What you would want it to do

## Does it need new Graph permissions?

The assessment deliberately runs on four read-only delegated scopes: `Policy.Read.All`,
`AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`. Anything requiring more
than these is a significant change rather than an increment — it is the reason legacy
per-user MFA state is not read today.

Beta endpoints are a smaller matter but still worth flagging. The assessment reads one,
`beta/policies/authenticationMethodsPolicy`, for a field that has no v1.0 equivalent;
Microsoft does not guarantee beta stability, so a new one needs a reason and a soft
failure path.

- [ ] Works within the existing four scopes
- [ ] Needs additional scopes (say which, and what it would buy)
- [ ] Needs another beta endpoint (say which, and why v1.0 cannot answer it)

## Does it write anything?

Every Graph call in the assessment, the sweep, and the compare script is a GET, and
several design decisions exist only to keep it that way — the remediation group is
exported as a CSV rather than created, because creating it would be a write. The one
write tool in the repository, `Set-EntraPasskeyOptOut.ps1`, is a separate script that no
assessment path invokes, and it stays that way.

- [ ] Read-only
- [ ] Would require a write (explain why that is worth breaking the contract for)
