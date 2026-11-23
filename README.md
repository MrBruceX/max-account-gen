# MAX SHOP secure app (Node.js + PostgreSQL)

Requirements: Node.js 20+, PostgreSQL 14+, HTTPS in production. Server serves only `public/` and `/api`; repository files are not public.

1. Create private PostgreSQL database and least-privilege user.
2. Copy `.env.example` to `.env`; set DATABASE_URL, unique random SESSION_PEPPER and TOKEN_PEPPER, exact HTTPS PUBLIC_ORIGIN, COOKIE_SECURE=true, and trusted proxy configuration.
3. `npm install`; `npm run migrate` (Node 20.6+ loads `.env` via `--env-file`).
4. For local HTTP only set `COOKIE_SECURE=false` (uses a non-__Host development cookie); production must use HTTPS and `COOKIE_SECURE=true`. Create first owner from trusted terminal: `npm run bootstrap-admin -- owner@example.com "long-unique-password"` (12+ chars; refuses if an owner exists).
5. `npm start`; route frontend and /api through the same HTTPS origin.

The active UI is /, /generator.html, /admin.html. Server enforces auth, CSRF, licenses, revocation, inventory, quotas, admin operations, and report/settings changes. Raw license token is displayed only once. Customer-entered Discord IDs are claims, not verified identity; add Discord OAuth2 before relying on them for authorization. Configure TLS/HSTS, backups/restore tests, monitoring, DB restrictions, npm audit, integration tests and independent penetration testing before real use. Old chat/history was omitted instead of retaining insecure localStorage behavior.
