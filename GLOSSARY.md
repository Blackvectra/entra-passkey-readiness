# Entra SMS/Voice Passkey Readiness

Read-only assessment of how Microsoft's SMS/voice MFA retirement affects the users in an MSP's client tenants.

## Language

**Customer**:
The client organization an assessment is delivered to. A Customer may own more than one tenant.
_Avoid_: Client account, company

**Tenant**:
One Microsoft Entra ID directory, identified by its tenant ID or a verified domain. It is the unit that gets assessed.
_Avoid_: Customer (when you mean the directory), org

**Tenant Profile**:
The saved, non-secret settings needed to assess one Tenant: which Tenant, which Customer it belongs to, how to sign in to it, and who to leave out. Each Tenant has exactly one Tenant Profile.
_Avoid_: Profile (on its own), config, customer profile, connection
