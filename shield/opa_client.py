"""
Real OPA REST client for `policy_engine.engine.PolicyEngine`.

This module used to be a direct import of `integrity_sdk.policy.opa_client` -- but
integrity-core's Phase A1 restructure (docs/EXECUTION_PLAN.md) removed that module
entirely (it was BCC middleware's own client, vendored into the SDK and unused by
the SDK itself; A2 replaced it for SDK consumers with `integrity_sdk.core.opa.OpaClient`,
which speaks the new signed-pack decision contract, not this package's current raw
Rego-in-OPA shape). Importing the deleted module breaks at `import shield.policy_engine.engine`
time against any current `integrity-core` checkout.

This is a straight port of that module's behavior, not a rewrite: it is scoped to
un-break the import, not to change what a Shield policy evaluation does. Migrating
`PolicyEngine` onto `integrity_sdk.core.opa.OpaClient` and signed packs is tracked
separately (docs/EXECUTION_PLAN.md A3's "Policy bundles become signed packs..." item) --
that migration also needs a pack-signing key custody decision this port does not make.

Fails closed the same way the original did: a well-formed HTTP 200 from OPA with a
boolean `result.allow` is the only way to get a decision back. Every other outcome --
connection refused, timeout, non-200, malformed JSON, a missing `result` key, or a
`result` with no boolean `allow` -- raises `OPAUnavailableError`, and the caller
(`PolicyEngine.evaluate`) already treats that as an explicit deny.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx


class OPAUnavailableError(Exception):
    """OPA could not be reached or returned something that can't be trusted.

    Callers MUST deny the request when this is raised -- there is no fallback path.
    """


@dataclass
class OPADecision:
    allow: bool
    violations: list[str] = field(default_factory=list)
    requires_baa: bool = False
    raw_result: dict = field(default_factory=dict)


async def evaluate(opa_url: str, opa_package_path: str, opa_timeout_seconds: float, opa_input: dict) -> OPADecision:
    """Evaluate `opa_package_path` (e.g. `/v1/data/shield/policy`) against `opa_input`.

    Queries the package root rather than only an `/allow` leaf, so the same round
    trip also returns whatever else the package's `raw_result` carries (Shield reads
    `action`/`message`/`rule_id`/`name`/`version` out of it) -- this is still the
    identical `allow` rule a leaf-scoped query would evaluate.
    """
    url = f"{opa_url.rstrip('/')}{opa_package_path}"
    try:
        async with httpx.AsyncClient(timeout=opa_timeout_seconds) as client:
            resp = await client.post(url, json={"input": opa_input})
    except httpx.HTTPError as exc:
        # Connection refused, DNS failure, timeout, TLS error, etc. -- OPA is not
        # reachable. Fail closed: this is NOT a policy decision, so never synthesize
        # `allow=False` here and pretend it came from Rego; raise, and the caller
        # must treat "can't reach OPA" as its own explicit deny path.
        raise OPAUnavailableError(f"OPA request failed: {exc}") from exc

    if resp.status_code != 200:
        raise OPAUnavailableError(f"OPA returned HTTP {resp.status_code}: {resp.text[:500]}")

    try:
        body = resp.json()
    except ValueError as exc:
        raise OPAUnavailableError(f"OPA response was not valid JSON: {exc}") from exc

    if "result" not in body:
        # A package with no matching rules (e.g. a typo'd package path) comes back
        # as `{}` with no `result` key at all -- this must NOT be silently treated
        # as `allow=False` via `.get(..., False)`, because that would mask a broken
        # deployment (wrong policy path) as a normal policy denial forever. Surface
        # it loudly instead.
        raise OPAUnavailableError(f"OPA response missing 'result' (bad policy path {opa_package_path}?): {body}")

    result = body["result"]
    if not isinstance(result, dict) or "allow" not in result or not isinstance(result["allow"], bool):
        raise OPAUnavailableError(f"OPA result missing boolean 'allow' field: {result!r}")

    violations = result.get("violation", [])
    if not isinstance(violations, list):
        violations = [str(violations)]

    return OPADecision(
        allow=result["allow"],
        violations=[str(v) for v in violations],
        requires_baa=bool(result.get("requires_baa", False)),
        raw_result=result,
    )


async def is_reachable(opa_url: str) -> bool:
    """Cheap liveness probe for /health -- failures here are not security decisions."""
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(f"{opa_url.rstrip('/')}/health")
        return resp.status_code == 200
    except httpx.HTTPError:
        return False
