# Claude Handoff — Phase 3 Gate 1 Complete

Date: 2026-11-03
Project: Xibalba Integrity ecosystem
Current slice: Phase 3 Gate 1 — SDK runtime and identity canary
Status: **PASS WITH EXPLICIT WORKTREE-LAYOUT PREREQUISITE**

## Start here

Read the governing workflow before creating branches, worktrees, commits, or
pushes:

```text
/home/xibalba/.hermes/WORKFLOW.md
```

The approved Shield worktree is:

```text
/mnt/storage/xibalba/Projects/worktrees/xibalba-shield/phase3-gate1-sdk-runtime
```

Branch:

```text
test/phase3-gate1-sdk-runtime
```

Enter the worktree by path if using Claude tooling. Do not create a second
worktree for this slice and do not work in the read-only base checkout.

The Gate 1 evidence commit is:

```text
a8d73c2 docs: record phase 3 gate 1 sdk result
```

The detailed evidence is in:

```text
docs/handoffs/2026-11-03-phase3-gate1-result.md
```

## Architecture boundary

Phase 2 is approved. Gate 1 is complete. The following boundaries remain
binding:

- Shield remains the only enforcement authority.
- Cortex remains a separate profile-local memory/provenance product.
- Integrity-core remains the trust substrate and sole SDK authority.
- Oracle/scoring-core remains the sole AIS authority.
- Shield and Cortex UIs remain independent.
- No Shield-to-Cortex event wiring has been authorized by Gate 1.
- No service installation, restart, host mutation, identity regeneration,
  credential change, database/WAL change, queue/outbox change, or public-chain
  operation is authorized in this handoff.

## Frozen SDK authority

Use only this existing Core SDK source:

```text
/home/xibalba/Projects/integrity-core/integrity-sdk
```

Frozen Core revision:

```text
d460736cc499101b5b4d326c85b9bf817699bf59
```

SDK version: `0.1.0`

Do not copy, vendor, fork, regenerate, or replace the SDK. Do not create a
second signing or identity implementation.

## Gate 1 evidence

### Cortex

Worktree:

```text
/mnt/storage/xibalba/Projects/worktrees/xibalba-cortex/phase3-gate1-sdk-runtime
```

Verified:

- `xb-wt setup` passed.
- `uv lock --check` passed.
- Runtime import resolved to the frozen Core SDK source.
- Focused identity, canonicalization, and SDK outbox tests passed: 11 tests.

### Shield

Verified with the existing declared sibling SDK layout:

- `uv sync` passed.
- `uv lock --check` passed.
- Runtime import resolved to the frozen Core SDK source.
- Focused signing, canonicalization, agent-binding, and redaction tests
  passed: 16 tests.

The sibling SDK link used for this validation was temporary and was removed.
Confirm that `../integrity-core` is absent from the Shield worktree parent
before making any further setup decision.

### Identity canary

The existing test DID was loaded without identity generation or copying:

```text
/home/xibalba/.integrity/did/xibalba-shield-test
```

DID:

```text
did:integrity:e39591abaa0fa222604913d8e5e24cbb621d860c5a367c36243f37d175f9f447
```

Canonical body SHA-256:

```text
e95bba79bc45dfdd055807ba699ea45e15af66287d91d9a130dd05051a083dff
```

Signature verification passed. The private-key mtime and BCC nonce were both
unchanged. Never print or copy private key material.

## Known prerequisite

Both consumers currently declare the editable SDK path:

```text
../integrity-core/integrity-sdk
```

This resolves in the normal sibling checkout layout, but a newly created
Shield worktree under `/mnt/storage/xibalba/Projects/worktrees/...` does not
automatically contain the sibling path. Running `xb-wt setup` in the Shield
Gate 1 worktree without that layout fails with a missing distribution error.

Do not solve this by committing an absolute `/home/xibalba/...` path. Do not
silently create a permanent external symlink. Gate 2 must first select and
document a reproducible layout mechanism that works for local worktrees and
CI while retaining Core as the authority.

## Recommended Gate 2 objective

Resolve the SDK path-layout prerequisite without changing runtime ownership or
product boundaries.

Acceptance criteria:

1. A clean prescribed Shield worktree can resolve the frozen Core SDK through
   the declared dependency mechanism.
2. Cortex and Shield both resolve the same frozen Core revision.
3. CI can reproduce the same layout without a developer-only absolute path.
4. `uv lock --check` and the focused SDK tests pass for both consumers.
5. No installed service, base checkout, identity store, credential, database,
   queue, or outbox is changed.
6. The result is documented in a new handoff before any event wiring begins.

Stop after documenting Gate 2. Do not begin Shield-to-Cortex wiring in the
same slice unless separately authorized.

## Safety commands

From `/home/xibalba`:

```bash
xb-wt doctor
xb-wt list
```

From the Shield worktree:

```bash
git status --short --branch
git log -1 --oneline
test ! -e ../integrity-core && echo 'no temporary SDK link'
```

Never use `git stash`. Use a WIP commit if preservation is required. Never
push with bare `git push`; use `xb-wt push` only after the user requests a
push and the relevant CI evidence is available.
