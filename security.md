# LockItPDF Security Guide

## Implemented Controls

- Passwords are stored with Argon2id via `argon2-cffi`. Legacy Werkzeug hashes are verified once and rehashed on successful login.
- Server-side sessions are stored in the runtime data store as HMAC-SHA256 token hashes. Cookies are `HttpOnly`, `SameSite=Strict`, expire after `LOCKITPDF_SESSION_TTL`, and use `Secure` in production.
- Email verification and password reset use cryptographically random, hashed, single-use tokens with `LOCKITPDF_TOKEN_TTL`.
- Login, signup, recovery, password reset, and upload endpoints are rate limited with Flask-Limiter.
- Failed login attempts use exponential retry hints and lock accounts after `LOCKITPDF_FAILED_LOGIN_LIMIT`.
- API endpoints require authentication where user data or files are accessed. Downloads check `job.owner_id == current_user.id`.
- Uploads are restricted to PDF extension, MIME type, `%PDF-` magic bytes, and `LOCKITPDF_MAX_UPLOAD_MB`.
- Runtime uploads and outputs live in `LOCKITPDF_DATA_DIR`, outside the web root by default, with TTL cleanup via `LOCKITPDF_JOB_TTL`.
- Security headers include `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and production HSTS.
- Auth events, rate limits, account locks, and admin actions are logged without raw passwords or full tokens.

## Required Environment Variables

Use a cloud secrets manager or platform-managed environment variables in production. Do not commit `.env` files.

```txt
DATABASE_URL
SESSION_SECRET
JWT_SECRET
FRONTEND_ORIGIN
APP_BASE_URL
LOCKITPDF_ADMIN_EMAIL
LOCKITPDF_DATA_DIR
LOCKITPDF_SESSION_TTL
LOCKITPDF_TOKEN_TTL
LOCKITPDF_JOB_TTL
LOCKITPDF_MAX_UPLOAD_MB
LOCKITPDF_FAILED_LOGIN_LIMIT
LOCKITPDF_LOCKOUT_SECONDS
RATELIMIT_STORAGE_URI
SMTP_HOST
SMTP_PORT
SMTP_USER
SMTP_PASS
SMTP_FROM
```

Optional production controls:

```txt
LOCKITPDF_CAPTCHA_SECRET
LOCKITPDF_CAPTCHA_ON_SIGNUP
LOCKITPDF_CAPTCHA_FAILURE_THRESHOLD
LOCKITPDF_ALERT_WEBHOOK_URL
LOCKITPDF_AV_SCANNER
```

## Operational Guidance

- Set `ENV=production`, `COOKIE_SECURE=true`, and serve only behind HTTPS.
- Configure `FRONTEND_ORIGIN` to the exact public frontend origin; broad CORS origins are intentionally not used.
- Use Redis or another shared backend for `RATELIMIT_STORAGE_URI` when running multiple workers.
- Store `LOCKITPDF_DATA_DIR` on private storage. Do not mount it under a public static directory.
- Add antivirus scanning before public launch. If `LOCKITPDF_AV_SCANNER` is unset in production, uploads are logged as needing manual review.
- Restrict database access to a private network or VPC and never expose it directly to the public internet.
- Forward rate-limit, account-lock, and admin-action logs to monitoring. `LOCKITPDF_ALERT_WEBHOOK_URL` is reserved for webhook integration.

## Existing User Migration

1. Deploy this code with `SESSION_SECRET`, SMTP settings, and runtime storage configured.
2. Keep the existing user store available to the Flask app.
3. On each successful login, legacy hashes are verified and replaced with Argon2id.
4. Encourage users to log in during a migration window, then force password resets for accounts that still have legacy hashes.
5. Enable `REQUIRE_EMAIL_VERIFICATION=true` after SMTP delivery is confirmed.

## Rollback Plan

1. Keep a backup of the pre-migration user store and runtime files.
2. If authentication fails after deployment, disable traffic to the new container and restore the previous version.
3. Preserve the new user store for audit, because some accounts may have already been upgraded to Argon2id.
4. Rotate `SESSION_SECRET`, SMTP credentials, and any deployment secrets if rollback was caused by suspected exposure.
5. Re-run tests and a small canary login/upload flow before retrying deployment.
