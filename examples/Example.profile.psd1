# Example Tenant Profile. FICTIONAL: copy it to profiles/<name>.profile.psd1 and edit.
#
# One file per tenant. The file name without ".profile.psd1" is the profile name you pass
# to -TenantProfile; use letters, digits and hyphens only.
#
# This is a PowerShell data file. It is read with Import-PowerShellDataFile, so it can hold
# only literal values and cannot run code. Any key not listed below is refused.
#
# NEVER put a secret here: no client secret, no password, no private key. A certificate
# thumbprint is fine; it names a certificate in your store and is useless without its key.
# Real profiles are git-ignored. Do not commit one.
@{
    # Required. Always 1 for this version of the scripts.
    SchemaVersion         = 1

    # Required. The tenant GUID or a verified domain. A sign-in name (user@domain) or
    # 'common'/'organizations' is refused, because a profile must name exactly one tenant.
    TenantId              = 'fabrikam-example.onmicrosoft.com'

    # Required. The Customer this tenant belongs to. It names the reports/ folder and
    # appears in reports and tickets. Several tenants of one Customer share this value.
    CustomerName          = 'Fabrikam Clinic Group'

    # Optional, for app-only (unattended) sign-in. The application (client) ID of the
    # read-only app registration, and the thumbprint of its certificate in your store.
    # Leave both out to sign in interactively.
    ClientId              = '00000000-1111-4222-8333-444444444444'
    CertificateThumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'

    # Optional. Regular expressions matched against the UPN. Matching users are marked
    # Excluded and left out of every count. Keep these narrow.
    ExcludeUpnPattern     = @('^svc-', '^noreply@')

    # Optional. Where ticket history for this tenant is kept. Omit to use the default in
    # the tenant's reports/ folder.
    # TicketHistoryPath   = 'D:\MSP\fabrikam\TicketHistory.json'
}
