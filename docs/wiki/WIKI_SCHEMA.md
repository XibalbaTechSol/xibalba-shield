# Xibalba Shield Wiki — Schema (v1)

## Domain

The compiled knowledge base for Xibalba Shield: a Linux-first endpoint security agent for the
age of AI agents. It is both an AI-agent-aware and legacy-endpoint security agent — deterministic
local policy enforcement, OS-level process containment, semantic guardrail hooks for
instrumented agent runtimes, and signed evidence export into the Integrity Protocol.

## Conventions

- **Canonical source**: `xibalba-shield/docs/wiki/` on the main branch is the only authoring
  source of truth. The repository's GitHub Wiki is a generated, read-only projection of these
  files. Do not author or reconcile content in the GitHub Wiki mirror; the next sync may
  overwrite it.
- **Table of contents**: every canonical article contains a generated `## Table of contents`
  block covering its level-two and level-three headings. Run `python3 scripts/wiki_toc.py` after
  heading changes and `python3 scripts/wiki_toc.py --check` in validation. Do not hand-edit the
  generated block.
- **Filenames**: lowercase, hyphenated, `.md` (e.g. `action-broker.md`).
- **Wikilinks**: use `[Title](relative/path.md)` to interlink entities/concepts/acronyms. Minimum
  2 outbound links per page.
- **Frontmatter**: required on every page (template below).
- **Index sync**: every new page is added to `WIKI_INDEX.md` in the same pass it's created.
- **Append log**: every creation/update is logged in `WIKI_LOG.md` (append-only).
- **No aspirational content**: only document what exists in the code. Planned-but-unbuilt is
  marked `[PLANNED]`. Where the code itself is ambiguous, undocumented, or contradicts other
  repository documentation (e.g. a stale README claim), say so explicitly rather than picking
  whichever version is more flattering.
- **No duplication**: each fact lives on exactly one canonical page; others link to it.
- **Code over prose**: include real function signatures, schemas, or CLI commands, not paraphrase.

## Frontmatter template

```yaml
---
title: Page Title
acronyms: [optional, e.g. DID, BCC]
created: YYYY-MM-DD
updated: YYYY-MM-DD
type: entity | concept | comparison | query
tags: [see taxonomy below]
confidence: high | medium | low
source_files:
  - relative/path/to/file
---
```

### Confidence scoring

| Level | Meaning |
|---|---|
| `high` | Verified against source within the last 14 days |
| `medium` | Previously verified; source may have changed since, or the page documents a real, unresolved gap/drift the reader needs to weigh — needs review |
| `low` | Carried over from a spec/plan, not yet verified against real code |

## Tag taxonomy

- `enforcement` — policy evaluation, decision routing, the event pipeline
- `containment` — OS-level process containment (Action Broker)
- `sensors` — eBPF probes, dev-mode synthetic sensor, platform stubs
- `compliance` — evidence export, audit trail, SIEM/SOAR, tamper evidence
- `slm` — the Tier-2/Tier-3 cascade, local small-language-model inference
- `infrastructure` — config, CLI, identity/DID, cross-cutting plumbing

## Directory structure

- `entities/` — packages, services, and stateful components with a single canonical owner
- `concepts/` — mechanisms, protocols, and architectural patterns shared across modules
- `architecture/` — cross-cutting data-flow / sequence docs, ecosystem positioning
- `queries/` — open research questions, investigation notes (not conclusions)

## Publication flow

```text
xibalba-shield/docs/wiki
        └── scripts/sync_wiki.py ──> GitHub Wiki
```

Unlike `integrity-core`, Shield has no second downstream consumer (no dashboard/MVP wiki
projection) — the GitHub Wiki mirror is the only generated output of this source tree.

## Source binding rule

Every page's `source_files` must list real files that exist right now. If a listed file is
deleted or renamed, the page is stale — fix it or remove the page in the same pass that changes
the code.
