@{
    # Rules are enforced in CI. Two are excluded deliberately; both exclusions are
    # design decisions rather than deferred cleanup, so they are documented here
    # rather than suppressed inline at each site.
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # PSAvoidUsingWriteHost
        # This is an operator-facing assessment tool, not a library. The coloured console
        # summary is a deliberate part of the deliverable: it is what a technician reads
        # before opening the CSV, and severity is carried by colour. Machine-readable
        # output already has its own channel: the summary object on the pipeline, the
        # CSV, the ticket queue, and the HTML report. Switching to Write-Output would put
        # narration into the pipeline and corrupt the object the sweep runner captures.
        'PSAvoidUsingWriteHost'

        # PSUseShouldProcessForStateChangingFunctions
        # Fires on New-HtmlReport, New-TicketExport, and New-Ticket purely on the verb.
        # These are private helpers inside a script that is already gated by explicit
        # opt-in switches (-HtmlReport, -ExportTickets); the caller has already stated
        # intent. Adding -WhatIf/-Confirm to internal helpers would imply the script
        # mutates tenant state, which is the opposite of what it does. Every Graph call in
        # the assessment, the sweep, and the compare script is a GET.
        #
        # The exclusion is repo-wide, so it is worth saying what it does not hide. The one
        # script that does mutate tenant state, Set-EntraPasskeyOptOut.ps1, declares
        # SupportsShouldProcess with ConfirmImpact = 'High' and gates its PATCH behind
        # ShouldProcess anyway, so it satisfies the rule on its own rather than by
        # exemption. If that ever stops being true, this comment is the lie to fix first.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
