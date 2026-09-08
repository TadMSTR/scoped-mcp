## What and why

<!-- The diff shows what changed. Explain why. -->

## Checklist

- [ ] Tests added or updated, and they fail against the code without this change
- [ ] `pytest` passes; coverage still above 80%
- [ ] `ruff check .` and `ruff format --check .` clean
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] No real hostnames, tokens, room IDs or internal addresses in tests, examples or docs

## If this touches verification, redaction or storage

- [ ] No path accepts a request when its secret is missing or empty
- [ ] Credential comparisons use `hmac.compare_digest`
- [ ] HMAC is computed over the raw request bytes, before decoding
- [ ] Nothing new reaches the event log un-redacted
- [ ] A negative test covers the failure case, not only the success case
