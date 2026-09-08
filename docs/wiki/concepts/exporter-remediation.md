---
title: Exporter Remediation
created: 2026-09-08
updated: 2026-09-08
type: concept
tags: [enforcement, compliance, infrastructure]
confidence: high
source_files:
 - shield/backend/remediation.py
 - shield/remediation_worker.py
 - shield/config/tls.py
 - shield/backend/api.py
 - shield/watchdog.py
 - tests/test_remediation_api.py
 - tests/test_remediation_worker.py
 - tests/test_remediation_store.py
---

Shield has a bounded control-plane recovery loop for the
[Integrity Exporter](integrity-exporter.md). It is not a remote shell or a general
endpoint-remediation framework.

## Table of contents

- [Lifecycle and authentication](#lifecycle-and-authentication)
- [Supported actions](#supported-actions)
- [Failure and evidence boundary](#failure-and-evidence-boundary)

## Lifecycle and authentication

An authenticated tenant admin creates a request with
`POST /api/shield/exporter-remediation`. Only `retry`, `flush`, and
`reconnect` are accepted. The enrolled device uses its own bearer token to call:

```text
GET  /api/shield/exporter-remediation/next?tenant_id=...&device_id=...
POST /api/shield/exporter-remediation/complete
```

`claim_next()` atomically transitions the oldest matching request from `queued`
to `running` and creates one attempt row. Completion accepts only `completed` or
`failed`, records structured detail, and is scoped to the same tenant and device.
The admin listing returns both requests and attempts.

The [watchdog](../architecture/enforcement-pipeline.md) asks
`RemediationWorker.run_once()` to claim at most one request per tick. Poll failures
are logged and do not terminate local enforcement.

When the device backend URL is HTTPS, `_request()` builds the same verified client context as
the runtime-status publisher and policy distributor. A configured CA bundle establishes server
trust and the configured client certificate/key establish mTLS; incomplete certificate pairs or
TLS settings on an HTTP URL fail closed. The local development CA used in the 2026-09-08 live
gate is not production trust material.

## Supported actions

- `retry` calls `IntegrityExporter.replay_pending()`.
- `flush` flushes current telemetry and then replays the durable spool.
- `reconnect` performs a fresh replay request because the exporter uses
 request-scoped HTTP rather than a persistent socket.

No action executes a command, changes policy, kills a process, or bypasses the
[Action Broker](action-broker.md).

## Failure and evidence boundary

Worker failures are reported as terminal `failed` attempts with structured error
detail when the completion call succeeds. A network failure can prevent that report,
so a request may remain `running`; lease/requeue recovery for abandoned claims is
not implemented. Unit/API tests prove lifecycle and dispatch behavior locally, not
production delivery, multi-replica coordination, or privileged host remediation.
