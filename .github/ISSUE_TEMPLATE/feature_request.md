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

The tool deliberately runs on four read-only delegated scopes: `Policy.Read.All`,
`AuditLog.Read.All`, `User.Read.All`, `GroupMember.Read.All`. Anything requiring more
than these, or requiring beta endpoints, is a significant change rather than an
increment — it is the reason legacy per-user MFA state is not read today.

- [ ] Works within the existing four scopes
- [ ] Needs additional scopes or beta endpoints (say which, and what it would buy)

## Does it write anything?

Every Graph call in this project is a GET, and several design decisions exist only to
keep it that way — the remediation group is exported as a CSV rather than created,
because creating it would be a write.

- [ ] Read-only
- [ ] Would require a write (explain why that is worth breaking the contract for)
