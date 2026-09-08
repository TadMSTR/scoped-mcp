---
name: Feature request
about: Suggest a capability
labels: enhancement
---

<!--
Please check the non-goals in the README first. Outbound webhook delivery, a scripting engine,
and multi-tenancy are deliberate exclusions with reasoning in ARCHITECTURE.md — a request for
one of those is welcome, but lead with why the reasoning does not hold for your case.
-->

## The problem

What are you trying to do that you cannot do today?

## Is this a new source?

Adding a producer should be a `config.yml` entry, not code. If you cannot express yours in YAML,
say what it does — a gap in the config schema is more useful to know about than a feature request.

- Producer:
- How it authenticates (signature header and format, a token header, or nothing):
- Payload shape, if it matters:

## What you have tried

Which `verify` strategy, and how it fell short.
