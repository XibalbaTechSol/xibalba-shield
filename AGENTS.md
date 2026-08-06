# Repository Guidelines

## Project Structure & Module Organization

`shield/` contains the Python package. Core routing and logs live in `agent_core/`, JSON config and policy distribution in `config/`, guardrail hooks in `guardrail_hooks/`, Integrity export code in `integrity_exporter/`, deterministic policy evaluation in `policy_engine/`, event/rule dataclasses in `schemas/`, Linux/dev sensors in `sensors/`, and SIEM/SOAR adapters in `integrations/`. `shield/cli.py` is the operator CLI. Tests are under `tests/`. Default policy bundles are in `policies/defaults/`; systemd assets are in `packaging/systemd/`; helper and validation scripts are in `scripts/`; design/runbook/audit docs are in `docs/`.

## Build, Test, and Development Commands

Use Python 3.12. For local development:

```bash
uv venv --system-site-packages .venv
uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/python -m pytest
```

`python3 scripts/e2e_validate.py` runs the root-free suite, validates default policy packs, exercises the dev sensor loop, checks BTF availability, and reports root/live checks as `SKIP` when unavailable. Run `shield validate --rules policies/defaults/smb.json` before changing policy JSON. Use `shield run --sensor dev --device-id dev-1 --no-exporter --max-events 12` for a local synthetic loop.

## Coding Style & Naming Conventions

Follow existing Python style: 4-space indentation, type hints, dataclasses for structured records, explicit exceptions, and small stdlib-first modules. Keep event schema names and policy fields stable; they are cross-module contracts. Use snake_case for functions, modules, variables, and test files; use PascalCase for classes. Avoid silent mocks or fake security claims in code, tests, and docs.

## Testing Guidelines

Tests use `pytest` and are named `tests/test_*.py`. Add focused tests beside the behavior you change: CLI wiring in `test_cli.py`, backend API in `test_backend.py`, policy logic in `test_policy_engine.py`, and distribution/SIEM/DLP in `test_distribution_siem_dlp.py`. Root eBPF and live Integrity checks must skip honestly unless real dependencies exist.

## Commit & Pull Request Guidelines

Recent history uses short imperative subjects such as `Document Shield pilot gates and TCP sensor update`; `CONTRIBUTING.md` also allows Conventional Commit prefixes like `feat:`, `fix:`, `docs:`, and `test:`. Keep PRs focused. Include the problem, approach, validation commands/results, security or deployment risks, and any blocked follow-up work.

## Security & Configuration Tips

Security, identity, cryptography, deployment, database, and protocol-boundary changes require maintainer review before implementation. Never commit credentials, private keys, raw sensitive content, or customer data. Local HMAC logs are tamper-evident, not root-resistant; Integrity export is the off-device evidence path.
