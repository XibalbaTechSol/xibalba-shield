# Codex advisory worker boundary

The Codex worker is optional and unprivileged. It is not a policy engine, action broker, signer, or transaction broadcaster. OPA and the deterministic Shield policy engine remain authoritative for enforcement.

## Runtime separation

`xibalba-shield.service` owns the eBPF capabilities and local containment path. The separate `xibalba-shield-codex.service` runs as the `xibalba` user with no Linux capabilities, private devices, a protected home directory, and access only to the advisory spool.

The worker consumes bounded JSON event envelopes from `/var/lib/xibalba-shield/codex/inbox` and writes advisory results to `outbox`. It redacts credentials, private keys, calldata, command lines, and sensitive paths before invoking Codex. Results are labeled `advisory_only`.

## Deployment boundary

The unit is a deployment template. Before enabling it, an installer must provision spool directories with ownership and permissions that allow the native service to write events and the unprivileged worker to read them. Do not grant the worker access to `/etc/xibalba-shield`, wallet material, the Shield control socket, or the native service logs.

The worker is not enabled by the native Shield unit automatically. This prevents an unreviewed LLM integration from becoming a hidden production dependency.
