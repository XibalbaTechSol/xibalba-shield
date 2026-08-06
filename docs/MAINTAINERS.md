# Maintainer Guide

## Triage

1. Remove secrets or sensitive data from public reports before continuing.
2. Confirm the issue is reproducible and within repository scope.
3. Apply `good first issue` only when the task is bounded, has acceptance criteria, and does not require privileged credentials or architectural authority.
4. Apply `help wanted` when the work is useful but requires broader context.
5. Use Discussions for design exploration; convert a settled proposal into an issue with acceptance criteria.
6. Link related issues and pull requests rather than creating duplicates.

## Review boundaries

Require maintainer review before accepting changes involving:

- Identity, authentication, authorization, cryptography, or trust boundaries.
- Deployment, workflows, secrets, or production controls.
- Database migrations, data retention, or tenant isolation.
- Protocol, schema, API compatibility, or cross-package behavior.
- Security, privacy, licensing, or user-impacting defaults.

## Good-first-issue standard

A good first issue must include:

- A specific outcome.
- Files or subsystem orientation.
- Acceptance criteria.
- A validation command that can run without privileged credentials.
- Explicit non-goals.
- No hidden dependency on unreleased architecture or private infrastructure.

## Pull-request review

Check behavior, tests, failure paths, security boundaries, documentation, compatibility, observability, and rollback. Do not reward a green build achieved by weakening tests, deleting checks, or hiding an uncertainty.

## Discussion prompts

Use Discussions to collect implementation-independent context. Good prompts ask one concrete question, state current evidence, list trade-offs, and identify a decision deadline or next experiment.
