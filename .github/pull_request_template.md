<!--
Before you write anything else: this repository must never contain live tenant
evidence. If you are pasting output to illustrate a problem, redact it or rebuild
it from the fictional samples in examples/.
-->

## What this changes

<!-- One or two sentences. What behaviour is different after this merges? -->

## Why

<!-- The problem being solved. Link the issue if there is one. -->

## How it was verified

<!-- What you actually ran. "Ran the tests" is enough if you ran them; say so if you
     could not test against a live tenant, and say what that leaves unverified. -->

- [ ] `Invoke-Pester ./tests` passes
- [ ] `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1` is clean
- [ ] Tested against a real tenant <!-- if not, say so above and note what is unverified -->

## Checklist

- [ ] **The assessment is still read-only.** Every Graph call added or changed outside `Set-EntraPasskeyOptOut.ps1` is a GET. If this PR introduces a write anywhere else, say so explicitly here and explain why it does not belong in a separate script — the assessment's contract is that it changes nothing.
- [ ] **No live tenant data** in the diff, the tests, the examples, or the PR description.
- [ ] Documentation updated if behaviour, parameters, or risk bands changed — including `docs/Risk-Classification.md` if the classification logic moved.
- [ ] `CHANGELOG.md` updated under `[Unreleased]`.
- [ ] Any new date, deadline, or Microsoft behaviour claim is cited to Microsoft Learn, not to another tool's output.
