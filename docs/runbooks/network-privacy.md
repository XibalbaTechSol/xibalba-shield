# Network Shield privacy and redaction

Redaction occurs at the observation point before network telemetry enters the Shield/Hermes
spool. Network events contain opaque references, coarse classifications, counters, and bounded
timestamps—not raw packet payloads or customer identifiers.

The default-deny boundary excludes raw IPs, MACs, SSIDs, hostnames, domains, URLs and query
strings, usernames, email addresses, authorization data, cookies, certificate subjects,
documents, VPN contents, and decrypted TLS content. TLS metadata is not plaintext visibility.

If a local operator needs to resolve an opaque reference, the mapping must remain local, access
controlled, audited, and separately authorized. Hermes and Cortex receive only the redacted
representation. Uncertain redaction fails closed.
