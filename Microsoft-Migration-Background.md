# Microsoft Migration Background

Context for the retirement of Microsoft-provided SMS and voice authentication in Microsoft Entra ID. Verify dates against Microsoft Learn before quoting them to a client; the timeline has already been revised once and rollouts are phased.

## What is changing

Microsoft announced on July 13, 2026 that it is retiring **Microsoft-provided telecom delivery** for SMS and voice authentication in Entra ID, and making passkeys the default authentication experience.

The scope qualifier matters. What is being retired is Microsoft's own delivery of text messages and phone calls. Unaffected:

- Microsoft Authenticator (push and TOTP)
- FIDO2 security keys and platform passkeys
- Windows Hello for Business
- Certificate-based authentication
- Hardware OATH tokens
- External and third-party MFA methods

Organisations with a regulatory or operational requirement for phone-based delivery can continue using it through a **customer-managed telecom provider** obtained via the Microsoft Security Store. That is a procurement and integration project, not a toggle.

## Timeline

| Date | Event |
|---|---|
| 2026-07-13 | Announcement published. |
| 2026-09-01 | Users enabled for SMS or voice in the Authentication Methods Policy **or in legacy per-user MFA** are auto-enabled for passkeys in AMP. The registration campaign is set to Microsoft managed and users are nudged to register at next successful MFA. Rollout is phased, so the date it reaches a given tenant varies. |
| 2026-09-18 | Customer-managed telecom provider pricing becomes available. |
| 2026-10-30 | Supported customer-managed providers can be configured. |
| 2027-02-01 | Microsoft-provided SMS and voice delivery is retired. Users whose only MFA method is a phone number can no longer satisfy MFA and face a mandatory registration prompt. |

A temporary opt-out is available for the 2026-09-01 through 2027-02-01 changes, to allow time for telecom provider configuration or migration to other methods. **There is no opt-out for the 2027-02-01 enforcement,** and it applies to all tenants.

To avoid the September auto-enablement entirely, users must be moved out of SMS and voice scope in the Authentication Methods Policy before that date.

## The two populations

The single most common planning error is treating these as one set.

**Policy scope** is the set of users targeted by the SMS or voice method in AMP. This drives the September 1 auto-enablement and the end-user nudge. It is typically the larger set, because `All users` targeting is common and predates any deliberate decision about phone-based MFA.

**Method registration** is the set of users who actually have a phone number registered. This drives who is blocked on February 1.

A tenant can have thousands of users in policy scope and a few dozen with a phone method registered. The first number sizes your communications and help-desk load; the second sizes your lockout risk.

## Why Entra cannot give you a clean SMS-versus-voice split

Entra does not store "SMS" and "voice" as two separate registrations. It stores a phone number with a type, and the type determines what that number can do:

| Registered method | SMS | Voice |
|---|---|---|
| `mobilePhone` | Yes | Yes |
| `alternateMobilePhone` | No | Yes (MFA only, not SSPR) |
| `officePhone` | No | Yes |
| `smsSignIn` | Yes (primary sign-in) | No |

There is no per-user attribute that says "this user uses SMS." Any tool claiming a clean split is inferring it. This script reports the registered phone methods and leaves policy scope to express intent, which is the honest representation of the underlying data.

## Legacy per-user MFA

Users enabled for SMS or voice through **legacy per-user MFA service settings** are in scope for the retirement even if the modern Authentication Methods Policy has both methods disabled.

This script deliberately does not read that state. Doing so requires beta Graph endpoints and broader delegated scopes, which would break the least-privilege model the tool is built around. Instead, the `Moderate` risk band exists to surface the symptom: a phone method registered on a user who does not resolve into modern AMP scope. A significant Moderate population is a prompt to check legacy per-user MFA settings manually.

Converting from legacy per-user MFA to the Authentication Methods Policy is worth doing on its own merits before this deadline, because it makes the exposure measurable.

## Practical migration sequence

1. **Measure.** Run this assessment. Run Microsoft's analyzer alongside it for the authoritative tenant-level policy and registration campaign view.
2. **Fix the Critical rows individually.** Privileged accounts and break-glass accounts get a FIDO2 key or platform passkey, verified by an actual test sign-in, before anything else happens.
3. **Create a security group** containing the SMS and voice population. Every subsequent step scopes to this group rather than to the whole tenant.
4. **Communicate before the nudge.** Awareness, then action, then reminder. Microsoft publishes end-user communication templates. A nudge that arrives before the communication generates tickets.
5. **Run a scoped registration campaign** rather than waiting for the Microsoft-managed default to fire.
6. **Decide on customer-managed telecom** only where a documented regulatory or operational requirement exists. Treat it as a procurement item with a lead time, not a fallback.
7. **Re-measure and track the delta.** The registration report lags, so measure on a cadence rather than expecting an immediate drop after a campaign.
8. **Remove SMS and voice from AMP scope** once the population is migrated, which is also what prevents the September auto-enablement for anyone remaining.

## References

- [Passkeys by default and retirement of Microsoft-provided SMS and voice authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement)
- [FAQ for Microsoft-provided SMS and voice retirement](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement-faq)
- [Microsoft's SMS/voice usage analyzer](https://github.com/microsoft/entra-sms-voice-usage-analyzer)
- [Graph API: list userRegistrationDetails](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0)
- [Authentication methods activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
- [Phone options for authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-phone-options)
