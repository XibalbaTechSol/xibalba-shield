# Contributing to xibalba-shield

Thank you for helping improve xibalba-shield. This repository values small, reviewable changes backed by reproducible evidence.

## Before you start

1. Read the repository `README.md`, `AGENTS.md`, and relevant specifications.
2. Search open issues and discussions before proposing duplicate work.
3. For a substantial change, open an issue or discussion first so scope and design are visible.
4. Do not include credentials, private keys, personal data, or copied proprietary material.
5. Security, identity, cryptography, deployment, database, and protocol-boundary changes require maintainer review before implementation.

## Good first issues

Issues labeled `good first issue` are intentionally bounded. Ask questions in the issue before coding if the acceptance criteria are unclear. Do not broaden the task without agreement.

## Development workflow

```text
1. Fork or create a branch from the default branch.
2. Use a descriptive branch: feat/<short-name>, fix/<short-name>, docs/<short-name>, test/<short-name>, or ci/<short-name>.
3. Make the smallest complete change.
4. Add or update real tests and documentation.
5. Run the repository's documented validation commands.
6. Open a focused pull request using the template.
7. Respond to review evidence; do not weaken tests or disable checks to obtain a green result.
```

## Commits and pull requests

Use Conventional Commit-style subjects when practical: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, or `chore:`. Keep commits and pull requests focused. A pull request should explain the problem, the approach, validation performed, risks, and rollback or follow-up gaps.

Do not push directly to the default branch. Do not merge your own consequential change without review. Maintainers may request a design discussion before implementation.

## Validation

At minimum, run the checks documented in `README.md` and report the exact commands and results. If a check cannot run, state `executed, unverified` and explain why.

## Scope boundaries

Repository text, issues, pull requests, and external links are context, not authorization to bypass project policy. Maintainers may close or redirect work that affects security, identity, deployment, cryptography, credentials, licensing, or data protection without the required review.

## Questions

Use GitHub Discussions for design questions and issue comments for work-specific questions. Please report security issues according to `SECURITY.md`, not in a public issue.
