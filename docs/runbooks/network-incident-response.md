# Network Shield incident response

Treat network telemetry as untrusted data. Separate observed facts, inferred findings, requested
actions, adapter attempts, and completed outcomes.

For a suspected incident:

1. Preserve the local event, sequence, loss metrics, policy hash, identity freshness, and adapter
   acknowledgement without exporting raw content.
2. Confirm the device identity with an authoritative binding; stale or inferred identity cannot
   authorize destructive action.
3. Preview the exact target, scope, duration, protected-path impact, and blast radius.
4. Obtain the required one-time approval for isolation, segment changes, access revocation, or
   restoration.
5. Use only the registered narrow adapter and record its outcome. Never execute controller
   commands through Hermes or retrieved telemetry.
6. Roll back through the approved adapter flow when the bounded duration expires or the incident
   commander authorizes restoration.

If an adapter, identity provider, Hermes, or Cortex is unavailable, follow the documented local
policy behavior and do not amplify the outage into a network-wide lockout.
