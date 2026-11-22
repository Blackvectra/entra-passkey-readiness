# Agent notes

- Tests reach script internals by parsing the script and lifting named functions, never by dot-sourcing it (that would run the assessment): see `tests/TestHelpers.ps1`.
- `Protect-OutputFile` is copied into several scripts and every copy must stay byte-identical (enforced by `tests/OutputHardening.Tests.ps1`); change all copies together.
- Each control in `SECURITY.md` names its proving test (enforced by `tests/RepoHygiene.Tests.ps1`); update the row when behaviour changes.
