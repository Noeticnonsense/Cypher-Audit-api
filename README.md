# Cipher Audit API for Render

A safe, authenticated Node/Express scaffold for the Base44 password-audit workflow.

## Render deployment

1. Upload these files to a private or public GitHub repository.
2. In Render, create **New > Web Service** and connect the repository.
3. Use:
   - Build command: `npm install`
   - Start command: `npm start`
   - Health check path: `/health`
4. Add the environment variable `AUDIT_API_TOKEN` with the exact same long secret used in Base44.
5. Deploy and copy the generated `https://...onrender.com` URL.
6. Set Base44 `AUDIT_API_BASE_URL` to that URL, without `/jobs` or a trailing slash.

## Authentication

All routes except `/` and `/health` require:

`Authorization: Bearer <AUDIT_API_TOKEN>`

## Included routes

- `GET /health`
- `GET /jobs`
- `POST /jobs`
- `GET /jobs/:id`
- `PATCH /jobs/:id`
- `POST /jobs/:id/start`
- `POST /jobs/:id/pause`
- `POST /jobs/:id/cancel`
- `GET /jobs/:id/results`
- `POST /jobs/:id/results`
- `POST /jobs/:id/verify`
- `POST /jobs/:id/reveal`
- `GET /audit-events`

## Important limitations

- Data is held in memory and is erased whenever Render restarts or redeploys the service.
- This package does not execute Hashcat, Fitcrack, John the Ripper, shell commands, or autonomous scans.
- The reveal route intentionally returns `501` until encrypted secret storage, role authorization, and recent MFA validation are implemented.
- For production, replace the in-memory maps with PostgreSQL and store sensitive recovered values in an encrypted vault.
