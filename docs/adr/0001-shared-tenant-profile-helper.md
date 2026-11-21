# Tenant Profiles are loaded by one shared, dot-sourced helper file

The assessment, sweep, GUI and compare scripts were each self-contained, but all four now need to load and validate Tenant Profiles. We put that logic, together with tenant-identifier validation, in a single `EntraSmsVoice.TenantProfile.ps1` that each script dot-sources. If the file is missing, the script fails immediately with a clear message. We chose this so a client auditing the tool reads one small file instead of four copies that could quietly drift apart, and so the "no secrets in a profile" checks are enforced in exactly one place.

## Considered Options

- **Copy the function into each script, with a test that fails when the copies differ**: keeps each script standalone, but leaves four copies of security-relevant validation to audit.
- **A PowerShell module**: the cleanest boundary, but it adds install and versioning work the project doesn't need yet.

## Consequences

The scripts are no longer single-file: copying one `.ps1` to another machine is not enough, and the helper has to travel with it.
