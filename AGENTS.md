# Repository Guidelines

## Project Structure & Module Organization

`shield/` contains the Python package. Core routing and logs live in `agent_core/`, JSON config and policy distribution in `config/`, guardrail hooks in `guardrail_hooks/`, Integrity export code in `integrity_exporter/`, deterministic policy evaluation (Tier 1 of the Hybrid Cascading Architecture) in `policy_engine/`, the local-OPA-profile smoke-run driver behind `shield local-run` in `opa_local.py`, the local SLM backend (Tier 2 of the cascade) in `slm_backend.py`, event/rule dataclasses in `schemas/`, Linux/dev sensors in `sensors/`, the FastAPI-style backend API (separate `shield-backend` CLI entry) in `backend/`, and SIEM/SOAR adapters in `integrations/`. `shield/cli.py` is the operator CLI. Tests are under `tests/`. Default policy bundles are in `policies/defaults/` (JSON; packaged Rego translations under `shield/policies/rego/`); the Tier-2 SLM training pipeline (QLoRA fine-tuning) is in `slm_training/`; systemd assets are in `packaging/systemd/`; helper and validation scripts are in `scripts/`; design/runbook/audit docs and the wiki are in `docs/`.

## Build, Test, and Development Commands

Use Python 3.12. For local development:

```bash
uv venv --system-site-packages .venv
uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/python -m pytest
```

`python3 scripts/e2e_validate.py` runs the root-free suite, validates default policy packs, exercises the dev sensor loop, checks BTF availability, and reports root/live checks as `SKIP` when unavailable. Run `shield validate --rules policies/defaults/smb.json` before changing policy JSON. Use `shield run --sensor dev --device-id dev-1 --no-exporter --max-events 12` for a local synthetic loop. Use `shield local-run --profile {smb,professional-services,regulated}` for a supervised local OPA profile smoke run (Rego bundle allowlisting + SHA-256 identity binding). `shield-backend` starts the backend API as a separate process.

## Coding Style & Naming Conventions

Follow existing Python style: 4-space indentation, type hints, dataclasses for structured records, explicit exceptions, and small stdlib-first modules. Keep event schema names and policy fields stable; they are cross-module contracts. Use snake_case for functions, modules, variables, and test files; use PascalCase for classes. Avoid silent mocks or fake security claims in code, tests, and docs.

## Testing Guidelines

Tests use `pytest` and are named `tests/test_*.py`. Add focused tests beside the behavior you change: CLI wiring in `test_cli.py`, backend API in `test_backend.py`, policy logic in `test_policy_engine.py`, and distribution/SIEM/DLP in `test_distribution_siem_dlp.py`. Root eBPF and live Integrity checks must skip honestly unless real dependencies exist.

## Commit & Pull Request Guidelines

Recent history uses short imperative subjects such as `Document Shield pilot gates and TCP sensor update`; `CONTRIBUTING.md` also allows Conventional Commit prefixes like `feat:`, `fix:`, `docs:`, and `test:`. Keep PRs focused. Include the problem, approach, validation commands/results, security or deployment risks, and any blocked follow-up work.

## Security & Configuration Tips

Security, identity, cryptography, deployment, database, and protocol-boundary changes require maintainer review before implementation. Never commit credentials, private keys, raw sensitive content, or customer data. Local HMAC logs are tamper-evident, not root-resistant; Integrity export is the off-device evidence path.
