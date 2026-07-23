# Cipher Audit API v2

A bounded backend for **authorized offline password auditing**. It executes Hashcat or John the Ripper inside a Docker container, using only an allowlisted wordlist attack. It does not perform credential stuffing, online login attempts, network exploitation, arbitrary shell commands, or autonomous lateral movement.

## Render deployment

1. Replace the files in your GitHub repository with this package.
2. In Render, change the service runtime to **Docker** or create a new Docker Web Service from the repository.
3. Keep `AUDIT_API_TOKEN` set to the same long value used by Base44.
4. Health check: `/health`.
5. Deploy. The health response should show `mode: bounded-live-worker` and engine availability.

Free Render instances are CPU-only, ephemeral, and sleep when idle. This backend is suitable for small proof-of-concept audits, not high-speed GPU cracking or durable job storage.

## Create a bounded audit job

`POST /jobs` with Bearer authentication:

```json
{
  "authorization_confirmed": true,
  "scope_confirmed": true,
  "engagement_id": "eng-123",
  "name": "Approved password audit",
  "engine": "hashcat",
  "hash_type": "sha256",
  "max_runtime_minutes": 10,
  "targets": [
    {"account_identifier": "test-user", "hash": "<authorized offline hash>"}
  ],
  "wordlist_entries": ["candidate-one", "candidate-two"]
}
```

Start it with `POST /jobs/{id}/start`, poll `GET /jobs/{id}`, then read `GET /jobs/{id}/results`.

Supported hash types: `md5`, `sha1`, `sha256`, `ntlm`, `bcrypt`, `md5crypt`, `sha512crypt`.

## Base44

Set:

- `AUDIT_API_BASE_URL=https://cypher-audit-api.onrender.com`
- `AUDIT_API_TOKEN=<same long token as Render>`

The plaintext reveal endpoint requires a reason and explicit authorization confirmation, returns `Cache-Control: no-store`, and logs the reveal. Add actual MFA verification in Base44 before calling it.
