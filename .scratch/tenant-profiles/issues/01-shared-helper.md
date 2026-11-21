# 01: Shared Tenant Profile helper
Status: ready-for-agent

Create `EntraSmsVoice.TenantProfile.ps1` with: profile-folder resolution, name validation, loading via Import-PowerShellDataFile, the key allow-list, thumbprint/SchemaVersion/TenantId validation, and a precedence merge with single and sweep modes. Move `Resolve-TenantIdentifier` into it. Add the gitignore rules, `examples/Example.profile.psd1`, ACL hardening and the world-readable warning, plus Pester and RepoHygiene tests. See spec.md.
