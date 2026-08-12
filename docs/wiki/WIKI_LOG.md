# Xibalba Shield Wiki — Log

> Chronological record of wiki actions. Append-only — never edit past entries.
> Actions: ingest, create, update, lint, query, archive

## [2026-08-12] create | Initial Shield wiki

- Seeded the initial `docs/wiki/` content tree for `xibalba-shield`, following the schema and
  conventions established in the sibling `integrity-core` repository's wiki.
- Wrote 7 concept pages: the enforcement pipeline's event router, the policy engine, the action
  broker, guardrail hooks, the Integrity exporter, the SLM cascade tiers, and the sensor model.
- Wrote 2 entity pages: device context/agent registry (merged onto one canonical page per the
  no-duplication rule — `AgentRegistry`'s distinct surface was too thin to justify a separate
  page), and the local event log.
- Wrote 2 architecture pages: the ecosystem role (Shield as the Immune System in the four-project
  ecosystem) and the end-to-end enforcement pipeline diagram tying the four core concept pages
  together.
- Wrote 1 query page: the compliance evidence trail, sharing its title with `xibalba-cortex`'s
  own page of the same name so the two repositories' compliance stories read as one narrative.
- Wrote `WIKI_SCHEMA.md`, `WIKI_INDEX.md`, and `index.md`, adapted from `integrity-core`'s wiki
  format for Shield's domain and tag taxonomy.
- Notable finding surfaced during this pass, documented on `concepts/policy-engine.md`: the
  committed `shield/policy_engine/engine.py` (as of commit `f86c0f0`, 2026-08-07, unchanged
  since) delegates rule evaluation to a local OPA sidecar rather than the table-driven in-process
  matcher `README.md` and `CLAUDE.md` still describe, and no `.rego` policy source for
  `shield/policy` exists in this repo or in `integrity-core` — flagged as a real, current
  documentation-vs-code drift rather than silently following the stale description.
- Ran `python3 scripts/wiki_toc.py` to generate every page's `## Table of contents` block, then
  verified with `python3 scripts/wiki_toc.py --check`.
