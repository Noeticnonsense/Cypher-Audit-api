# Cipher Audit API v3

This version adds authorized password-protected ZIP uploads using John the Ripper Jumbo and `zip2john`.

## Deploy

1. Replace the files in your GitHub `Cypher-Audit-api` repository with this package.
2. Commit to `main`.
3. In Render, deploy the latest commit. Keep the service runtime set to Docker.
4. Keep the existing `AUDIT_API_TOKEN` unchanged.
5. Open `/health` and confirm `jtr` and `zip2john` show `available`.

## ZIP endpoint

`POST /archives/zip` using `multipart/form-data` and `Authorization: Bearer <AUDIT_API_TOKEN>`.

Required form fields:
- `archive`: one `.zip` file
- `authorization_confirmed`: `true`
- `scope_confirmed`: `true`
- `wordlist_entries`: JSON array or newline-separated candidate passwords

Optional fields:
- `engagement_id`
- `organization_id`
- `name`
- `max_runtime_minutes`

The uploaded archive is deleted automatically after the job completes or fails.

## Base44 prompt

Add an Authorized ZIP Audit form to the Password Audit area. It must upload one `.zip` file through a Base44 server-side function to `/archives/zip` as multipart form data. Require written authorization, confirmed scope, a maximum runtime, and a bounded candidate wordlist. Never expose `AUDIT_API_TOKEN` in browser code. After upload, call `/jobs/{id}/start`, poll `/jobs/{id}`, display metadata from `/jobs/{id}/results`, and use the existing controlled reveal workflow for recovered passwords.
