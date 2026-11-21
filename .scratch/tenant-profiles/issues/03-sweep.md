# 03: Sweep runs from Tenant Profiles
Status: ready-for-agent
Blocked by: 01

Add `-TenantProfile <name[]>` and `-AllTenantProfiles`. Profile values win and Sweep-wide parameters only fill blanks. A duplicate TenantId refuses the run before any connection. Add a `TenantProfile` summary column. `-TenantListPath` stays unchanged. Add tests.
