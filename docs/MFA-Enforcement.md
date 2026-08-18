# Actually Enforcing MFA in a Tenant

A Conditional Access policy that says **Require multifactor authentication** is not the same thing as MFA being enforced. Most tenants that believe they have mandatory MFA have a policy that would enforce it, plus somewhere between one and eight reasons it does not, and none of those reasons show up as a warning anywhere in the portal.

This matters more than usual right now. From 2027-02-01 the SMS and voice methods that a lot of those users are quietly relying on stop working. A tenant whose MFA is real will see that as a registration campaign. A tenant whose MFA has holes in it will see it as a help desk queue, because the holes are exactly where the unregistered users are.

This document is a checklist for closing them. It is written for someone who has a policy in place already and wants to know whether it does anything.

---

## Why the policy alone does not do it

Ten ways a tenant with "Require MFA for all users" ends up not requiring MFA. Every one is common.

### 1. The policy is in report-only mode

Report-only collects the decision and does not act on it. Conditional Access evaluates report-only policies in phase 1 and skips them in phase 2, so the sign-in logs fill up with "would have required MFA" and everybody signs in with a password.

This is not usually an oversight at creation. It is a policy that was put into report-only during a rollout, generated a complaint, and never got switched back.

**Check:** every policy's state, not its name. `Report-only` and `On` sit next to each other in the list.

### 2. "Require one of the selected controls"

Conditional Access defaults to requiring *all* selected grant controls, but the common template — the one Microsoft itself publishes as an alternative for organisations not ready to require compliance — is **Require multifactor authentication, Require device to be marked as compliant, or Require Microsoft Entra hybrid joined device**, with **Require one of the selected controls**.

That is a legitimate policy. It is also a policy where anybody on a compliant or hybrid-joined device never performs MFA, which in a well-managed estate is nearly everybody. The tenant satisfies its policy every day without a single MFA prompt, and the day a user signs in from an unmanaged device is the day they discover they never registered a method.

**Check:** the grant control's AND/OR setting, not just its checkboxes.

### 3. Exclusions that accumulate

Every policy starts with two justified exclusions — break-glass accounts and directory synchronisation accounts — and Microsoft recommends both. What happens next is that a group called something like `CA-Exclusions-Temp` gets created during a migration, three people are added to it, and it is still there four years later with thirty.

**Check:** enumerate the exclusion groups and count the members. Then ask when each member was added and by whom. An exclusion nobody can explain is a finding.

### 4. Service principals are not covered at all

Microsoft is explicit: *calls made by service principals aren't blocked by Conditional Access policies scoped to users*. A user-scoped policy does nothing to an app registration or a managed identity, and an app with a client secret and `Mail.ReadWrite` is a mailbox compromise that no MFA policy touches.

**Fix:** Conditional Access for workload identities is a separate product surface with its own licensing (Microsoft Entra Workload ID). If that is not in the budget, the control is credential hygiene instead: certificate credentials over secrets, short expiry, and a regular review of who holds what.

### 5. Legacy authentication protocols cannot do MFA

IMAP, POP, SMTP AUTH, and older Exchange ActiveSync clients have no way to present a second factor. Microsoft's own figure is that more than 97% of credential stuffing and more than 99% of password spray attacks come in over these protocols.

There is a subtlety worth understanding: **Conditional Access is evaluated after first-factor authentication**. A CA policy blocking legacy auth stops the attacker getting in, but by the time it fires the password has already been verified — so it does not stop brute force, lockouts, or the attacker learning that the password is correct.

**Fix:** block basic authentication at the workload as well as in Conditional Access. In Exchange Online that is **Settings > Org Settings > Modern Authentication** in the Microsoft 365 admin center, backed by authentication policies; `AllowBasicAuthOutlookService` and `AllowBasicAuthReportingWebServices` can only be turned off from Exchange Online PowerShell.

### 6. Per-user MFA is still switched on underneath

This is the one that matters most for the SMS retirement, and the one this tool now reads directly.

Legacy per-user MFA is a separate enforcement layer with three states — `disabled`, `enabled`, `enforced`. It is not replaced by a Conditional Access policy; it sits alongside one. The consequences:

- A user left at `enforced` is prompted regardless of what Conditional Access says, so sign-in behaviour stops matching your policy and troubleshooting stops making sense.
- The per-user MFA **service settings** have their own trusted-IP bypass and their own "remember MFA on trusted devices" option, neither of which Conditional Access knows about. A user can be exempted from MFA by a setting in a portal nobody has opened in three years.
- A user moved to `enabled` who never completed registration stays at `enabled` forever; they do not transition to `enforced` on their own, and an administrator has to move them explicitly.

Microsoft's own recommendation (`switchFromPerUserMFA`) is to require MFA through Conditional Access and then **turn per-user MFA off for every user**. Not one or the other — the CA policy first, then disable per-user MFA, in that order.

**Check:** run this tool. The `PerUserMfaState` column reports every user's state, and `LegacyPerUserMfaInForce` in the summary is the count that should be zero.

### 7. An MFA claim already in the token

Conditional Access checks whether the token carries a satisfactory MFA claim, not whether the user authenticated in the last five minutes. With default session lifetimes and browser persistence, a user can go a long time between prompts. That is by design and it is fine — but it means "nobody is being prompted" is not evidence that the policy is off, and equally "we turned MFA on last week" is not evidence that anybody has done it yet.

**Fix:** where it matters, set **Sign-in frequency** and **Persistent browser session** explicitly rather than inheriting defaults.

### 8. Registration is a separate problem from enforcement

A Require-MFA policy does not get anybody registered. It waits until they hit a resource, then interrupts them into combined registration — over whatever network they happen to be on, on whatever device they happen to be holding.

Two consequences worth planning around:

- **Registration under interrupt is an attack surface.** An attacker with a stolen password and no second factor is delighted to be offered a registration wizard. Secure it with a Conditional Access policy on the **Register security information** user action, scoped to trusted locations, with Temporary Access Pass for people who genuinely cannot get to one.
- **Phishing-resistant methods cannot all be registered from interrupt mode.** If you set an authentication strength requiring one, users who are not already registered are blocked rather than helped. Register those methods *before* tightening the strength, not as a result of it.

Note also that from **2026-07-06** Conditional Access policies targeting **Register security information** will apply to Windows Hello for Business and macOS Platform SSO credential registration, which they do not today. Policies scoped to that user action should be re-tested in report-only before then.

### 9. Guests, and MFA you did not perform

For B2B collaboration, cross-tenant access settings can be configured to **trust MFA claims from the guest's home tenant**. That is often the right call — but the MFA in question happened in somebody else's tenant, under somebody else's policy, with methods you cannot see and cannot audit. Your policy is satisfied by an assertion.

**Check:** cross-tenant access settings per partner organisation, and whether your guests are excluded from policies you assume cover everyone.

### 10. Security Defaults and Conditional Access are mutually exclusive

Security Defaults enforces MFA registration and blocks legacy authentication for every user, with no configuration. Turning on Conditional Access requires turning Security Defaults off — and a tenant that switched them off to build "a proper policy set" and then built one incomplete policy is now less protected than it was before.

For Entra ID Free tenants, Security Defaults is the enforcement mechanism. Do not turn it off unless the replacement is finished.

---

## What to do, in order

1. **Inventory what you have.** Every Conditional Access policy, its state, its grant controls, its AND/OR setting, and every exclusion group with its current membership. If the tenant has fewer than a dozen policies this is a twenty-minute job and everything below depends on it.

2. **Turn per-user MFA off — after Conditional Access covers those users, not before.** Reversing the order removes enforcement from people who currently have it. Run this tool first so you know exactly who is affected, and check `LegacyPerUserMfaInForce` back to zero afterwards.

3. **Make the MFA requirement unconditional where you mean it to be.** If a policy is meant to require MFA, it should require MFA — not MFA-or-a-compliant-device. If you want the compliant-device path, that is a different policy with a different name, and it should be an explicit decision rather than a default that was never revisited.

4. **Cover the registration action.** A Conditional Access policy on **Register security information**, and a Temporary Access Pass process for the people it will otherwise strand. Do this before any registration campaign, not after.

5. **Block legacy authentication in two places.** Conditional Access (Exchange ActiveSync clients + Other clients → Block), and at the workload — Exchange Online modern authentication settings and authentication policies. The second is the one that actually stops password spray.

6. **Handle the non-human identities separately.** Service principals need workload identity policies or credential hygiene; they will never be covered by a user-scoped policy no matter how it is written.

7. **Get the methods registered before you tighten the strength.** Phishing-resistant authentication strength applied to a population that has not registered a phishing-resistant method locks that population out. Registration first, strength second — the same ordering this tool's per-user next steps use, for the same reason.

8. **Re-check, do not assume.** Move each policy to `On`, then verify from the sign-in logs that real sign-ins are being challenged, rather than from the policy list that they ought to be.

---

## How to verify it is real

The portal will not tell you. Three things that will:

| Source | What it answers |
|---|---|
| **Sign-in logs**, filtered on the Conditional Access tab | Which policies actually evaluated, and to what result, for real sign-ins. The only ground truth here. |
| [Multifactor authentication gaps workbook](https://learn.microsoft.com/entra/identity/monitoring-health/workbook-mfa-gaps) | Sign-ins that completed without MFA and why. Needs Log Analytics. |
| [Conditional Access gap analyzer workbook](https://learn.microsoft.com/entra/identity/monitoring-health/workbook-conditional-access-gap-analyzer) | Sign-ins no policy applied to at all. Needs Log Analytics. |

Without Log Analytics, the [user registration report](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity) is the fallback — and it is the same source this tool reads, so a run of `Get-EntraSmsVoiceMigrationImpact.ps1` gives you the registration side of the picture already.

---

## What this tool does and does not check

Being clear about the boundary, because a green report on one thing is easy to read as a green report on everything.

**It checks:**

- Which users are in scope of the SMS and voice authentication method policies, with nested groups and exclusions resolved — including whether any SMS target is enabled for first-factor sign-in, not just MFA.
- What each user actually has registered, and whether any of it survives the retirement.
- `BlockedAtRetirement` — whose only MFA method is a phone number, which is the population that stops working on 2027-02-01.
- Legacy per-user MFA state per user, on every run. This is item 6 above.
- The authentication methods policy migration state. Anything short of `migrationComplete` means the legacy per-user MFA service settings page and the legacy SSPR methods page still govern the tenant, and the console names both for a manual check — they are the one place SMS and voice can live that no API can read.
- Authentication strengths whose allowed combinations include SMS or voice, and the worse case: a strength with *nothing else left*, which becomes unsatisfiable outright at the retirement.
- A Conditional Access MFA inventory — every policy that requires MFA (built-in control or authentication strength), by name and state, including whether any grants through an SMS/voice-permitting strength. This is a partial answer to item 1: it tells you whether an enforcing policy *exists* and whether report-only mode is all you have.

**It does not check:**

- Conditional Access assignments, conditions, or exclusions. The inventory above says a policy exists and is on; whether its scoping actually covers every user (items 2, 3, 7, 8, and 9 above) is still manual.
- The legacy MFA service settings page and the legacy SSPR methods page themselves — no API exists for either. The tool tells you *whether* they still apply (the migration state); what they contain is a portal check.
- Whether legacy authentication is blocked, at either layer.
- Service principals and workload identities.
- Security Defaults state.
- Session lifetime and persistence settings.

The tool answers "who loses their sign-in method on 2027-02-01". This document answers "and is MFA even being enforced for them in the first place". They are different questions and a tenant can fail either one independently.

---

## Related

- [README](../README.md) — running the assessment
- [Operations-Playbook.md](Operations-Playbook.md) — running it across an estate
- [Risk-Classification.md](Risk-Classification.md) — how the bands are derived
- [Microsoft-Migration-Background.md](Microsoft-Migration-Background.md) — the retirement timeline
