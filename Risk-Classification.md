# Risk Classification

## Model

Risk is derived from three booleans and one attribute, evaluated in a fixed order. The first matching condition wins.

| Input | Source | Meaning |
|---|---|---|
| `InPolicyScope` | Resolved AMP include/exclude targets for `sms` or `voice` | User is targeted by the policy that drives the 2026-09-01 auto-enablement and nudge |
| `HasPhoneMethodRegistered` | `methodsRegistered` contains `mobilePhone`, `alternateMobilePhone`, `officePhone`, or `smsSignIn` | User has a method that stops working on 2027-02-01 |
| `IsPasswordlessCapable` | `isPasswordlessCapable` from the registration report | User already holds a method that survives the retirement. This is the mitigating control. |
| `IsAdmin` / `UserType` | Registration report and directory | Blast-radius modifiers |

`IsPasswordlessCapable` is the pivot. It is the only input that reflects a surviving control, so every band is fundamentally a statement about whether that control is present.

## Evaluation order

```
1. InPolicyScope AND HasPhoneMethodRegistered AND NOT IsPasswordlessCapable
     -> IsAdmin        : Critical
     -> UserType Guest : High
     -> otherwise      : High
2. InPolicyScope AND NOT IsPasswordlessCapable          -> High
3. HasPhoneMethodRegistered AND NOT IsPasswordlessCapable -> Moderate
4. InPolicyScope AND IsPasswordlessCapable              -> Low
5. HasPhoneMethodRegistered AND IsPasswordlessCapable   -> Low
6. otherwise                                            -> Informational
```

## Bands

### Critical
Privileged user, in AMP scope, phone method registered, no passwordless method.

This is the sign-in-lockout scenario applied to an account that can change tenant configuration. If this user is blocked on 2027-02-01 and the recovery path also depends on a phone number, the tenant has an availability problem on top of an authentication problem.

**Remediate first.** Register a FIDO2 security key or platform passkey. For break-glass accounts, confirm the exclusion strategy is documented and that at least one emergency-access account uses a method outside the retirement scope.

### High
Either the full exposure pattern on a standard or guest user, or a user in AMP scope with no passwordless method regardless of what is registered.

Condition 2 catches users who are targeted by policy but do not yet appear with a phone method: they will still be auto-enabled for passkeys on 2026-09-01 and nudged at next successful MFA. That is a help-desk volume event even where it is not a lockout event.

Guests are called out separately in the `Reason` field because passkey support for B2B and internal guest users follows a separate Microsoft timeline. Do not assume a guest can register a passkey on the same schedule as a member.

**Remediate in bulk.** Scope a registration campaign to this population, communicate ahead of it, and track registration completion.

### Moderate
Phone method registered, no passwordless method, but the user did **not** resolve into the modern AMP scope for SMS or voice.

This is the most diagnostically useful band. It usually means one of:

- SMS and voice are disabled in AMP, but phone numbers were registered under legacy per-user MFA service settings and were never cleaned up.
- The user is enabled for SMS or voice through legacy per-user MFA, which this script does not read and which is explicitly in scope for the retirement.
- The registration report is stale relative to a recent AMP change.

**Validate manually.** Check legacy per-user MFA service settings for this population before concluding they are unaffected. A large Moderate count with zero policy scope is a strong indicator of legacy MFA exposure.

### Low
The user is touched by the change but already holds a passwordless method. They will not be blocked. They may still see a nudge if they are in policy scope.

**Track, do not chase.** Optionally clean up the stale phone registration to reduce the account-recovery attack surface, which is worth doing independently of this retirement.

### Informational
No resolved exposure. Present in the CSV only when `-IncludeUnaffected` is supplied.

## Framework mapping

Use these when the output feeds a formal report rather than a work queue.

| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | `PR.AA-03` (authentication) | The retirement forces an authenticator-strength change; this assessment establishes current state. |
| NIST CSF 2.0 | `ID.AM-*` (asset and identity inventory) | Per-user method inventory is the input to the migration plan. |
| NIST SP 800-53 Rev. 5 | `IA-2(1)`, `IA-2(6)`, `IA-5` | Multifactor authentication and authenticator management. |
| NIST SP 800-63B | AAL2 / phishing-resistant AAL3 | Phone-based out-of-band authenticators are restricted; passkeys are the phishing-resistant target state. |
| CIS Controls v8 | `6.3`, `6.5` | MFA for externally exposed and administrative access. |
| MITRE ATT&CK | `T1621` (MFA Request Generation), `T1111` (MFA Interception) | The techniques that motivate the retirement. SIM swap and SMS interception fall here. |

## What this model does not claim

- It does not evaluate Conditional Access. A user in AMP scope may never be challenged; a user out of scope may still be blocked by a CA grant this script does not read.
- It does not predict whether a specific user will actually be blocked on 2027-02-01. It reports the conditions under which that becomes likely.
- Risk bands are an operational triage order, not a quantitative risk score. Do not aggregate them into a numeric tenant risk rating without saying so.
