# Phase 3 Gate 1 Result — SDK Runtime and Identity Canary

Date: 2026-11-03
Branch: `test/phase3-gate1-sdk-runtime`
Worktree: `/mnt/storage/xibalba/Projects/worktrees/xibalba-shield/phase3-gate1-sdk-runtime`

## Result

**PASS WITH EXPLICIT WORKTREE-LAYOUT PREREQUISITE**

The frozen Integrity-core SDK loads and operates correctly for both approved
consumers when the existing sibling-checkout layout is present. No Shield-to-
Cortex wiring was added. No installed service, credential, key, DID, database,
queue, or outbox was changed.

The current repository contract uses this editable source path in both
consumers:

```text
../integrity-core/integrity-sdk
```

That path resolves from the normal sibling checkout layout and from the Cortex
worktree because its parent already contains the expected SDK link. It does not
resolve from a newly created Shield worktree unless that sibling layout is
provided. This is recorded as an environment/layout prerequisite; it was not
silently changed to an absolute host path.

## Frozen SDK evidence

- Authority source: `/home/xibalba/Projects/integrity-core/integrity-sdk`
- Authority revision: `d460736cc499101b5b4d326c85b9bf817699bf59`
- SDK version: `0.1.0`
- Runtime module resolved to the frozen Core source tree for both consumers.
- No SDK copy, fork, vendored package, or replacement signing implementation
  was introduced.

## Identity and signing canary

The existing test identity was loaded read-only from:

```text
/home/xibalba/.integrity/did/xibalba-shield-test
```

Observed DID:

```text
did:integrity:e39591abaa0fa222604913d8e5e24cbb621d860c5a367c36243f37d175f9f447
```

The canary used the frozen SDK's canonical JCS and signed-body helpers.

- Canonical body SHA-256: `e95bba79bc45dfdd055807ba699ea45e15af66287d91d9a130dd05051a083dff`
- Signature verification: PASS
- Existing private-key mtime unchanged: PASS
- Existing BCC nonce unchanged: PASS
- No identity generation, copying, migration, or credential display occurred.

## Consumer checks

### Cortex

Worktree:
`/mnt/storage/xibalba/Projects/worktrees/xibalba-cortex/phase3-gate1-sdk-runtime`

- `xb-wt setup`: PASS
- `uv lock --check`: PASS
- Runtime import resolved to the frozen Core source: PASS
- Focused tests: `11 passed`

Tests covered identity resolution, signed SDK outbox consumption, and
canonicalization.

### Shield

Worktree:
`/mnt/storage/xibalba/Projects/worktrees/xibalba-shield/phase3-gate1-sdk-runtime`

- `uv lock --check` with the declared sibling layout: PASS
- Runtime import resolved to the frozen Core source: PASS
- Focused tests: `16 passed`

Tests covered signing adapter behavior, canonicalization, agent binding, and
redaction.

The sibling SDK link used for Shield validation was temporary and was removed
after the checks. The worktree contains no persistent SDK link or source
change.

## Boundary and next action

Gate 1 establishes SDK/runtime/identity readiness for the approved consumers,
subject to the existing sibling-checkout layout prerequisite. It does not
authorize Shield-to-Cortex event wiring, service installation, host mutation,
or a new identity path.

Before Gate 2, the project must choose and document a reproducible way for
`xb-wt` worktrees and CI to provide the already-frozen sibling SDK path. The
choice must preserve the Core source authority and must not use an absolute
developer-only path in committed metadata.
