# A profile sweep names tenant folders by Tenant Profile name, not CustomerName

A Customer can own several Tenants, so several Tenant Profiles can share a `CustomerName`. A tenant-list sweep names each output folder after the customer label, matches `-Resume` on it, and refuses duplicates. A profile sweep keyed the same way would refuse every multi-tenant customer. Instead, a profile sweep keys each Tenant's output folder and its `-Resume` match on the profile name, which is unique by construction. `CustomerName` still sets the report heading, the ticket company and the summary's `Customer` column.

## Consequences

Moving a client from `tenants.csv` to a profile changes its sweep folder from `ReportRoot/<CustomerName>/` to `ReportRoot/<profile name>/`. Its existing ticket history is not found unless the profile's `TicketHistoryPath` points at the old file. A `-Resume` across that switch re-assesses the client.
