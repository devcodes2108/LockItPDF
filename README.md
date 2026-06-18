# LockItPDF

LockItPDF is a web-based PDF password protection and recovery system. It uses a static HTML/CSS/JavaScript frontend, a Python Flask API, and a Python PDF-processing backend powered by `pikepdf`. The application lets registered users upload one or more PDF files, encrypt them with a strong password, optionally embed recovery questions, and later recover the password through the LockItPDF recovery workflow.

This README is written as both developer documentation and report/thesis reference material. It explains the project objective, architecture, modules, file usage, API endpoints, security mechanisms, setup process, testing, limitations, and future scope.

## Project Abstract

LockItPDF addresses the problem of protecting PDF documents with password-based encryption while also offering an optional recovery mechanism for users who may forget their password. Standard PDF readers do not provide a custom "forgot password" option for encrypted PDFs, so LockItPDF implements recovery outside the PDF reader through a dedicated web application. The system supports user authentication, secure password hashing, session cookies, rate limiting, file upload validation, PDF encryption, recovery-question embedding, password recovery, support queries, and an admin dashboard.

## Objectives

- Provide a simple browser interface for PDF encryption.
- Support regular password-based PDF encryption.
- Support recovery-enabled PDF encryption using security questions.
- Allow password recovery only for PDFs created with the recovery option.
- Protect user accounts with strong password rules and Argon2 password hashing.
- Use server-side HttpOnly session cookies instead of exposing tokens in JavaScript.
- Store temporary uploads and generated outputs in runtime folders.
- Provide admin visibility into users, activity logs, and support queries.
- Keep the application deployable locally, through Docker, or on a Python web host.

## Technology Stack

| Layer | Technology | Purpose |
| --- | --- | --- |
| Frontend | HTML, CSS, JavaScript | User interface, forms, upload flow, recovery flow, admin dashboard |
| API | Flask | Authentication, validation, routing, downloads, admin APIs |
| PDF processing | pikepdf / qpdf | PDF encryption and metadata handling |
| Security | Argon2, Flask-Limiter, HttpOnly cookies | Password hashing, rate limits, session protection |
| Email | SMTP | Email verification, password reset, optional admin support mail |
| Testing | pytest | API and security behavior tests |
| Deployment | Docker, Gunicorn | Containerized production execution |

## High-Level Architecture

```txt
User Browser
  |
  | HTML/CSS/JS pages
  v
Static Frontend
  |
  | fetch requests through assets/js/api-client.js
  v
Flask API (app.py)
  |
  | authentication, validation, sessions, jobs
  v
Python PDF Backend
  |
  | pikepdf encryption and recovery metadata
  v
Runtime Storage
```

## Main User Workflows

1. User signs up or logs in.
2. Flask creates a server-side session and sets the `lockitpdf_session` HttpOnly cookie.
3. User uploads one or more PDFs from `index.html`.
4. User enters a strong password.
5. User chooses regular encryption or recovery encryption.
6. Flask validates the request and calls the backend encryption module.
7. The encrypted PDF or ZIP is generated in `runtime/outputs/`.
8. User downloads the protected output through `/downloads/<job_id>/<filename>`.
9. If recovery mode was used, the user can later upload the recovery-enabled PDF on `recovery.html`, answer the questions, and recover the password.

## Project File Map and Usage

The project contains source files, configuration files, runtime/generated files, tests, and local cache files. For reports or thesis documentation, focus mainly on the source files and describe generated folders separately.

### Root Files

| File | Usage |
| --- | --- |
| `README.md` | Main project documentation, setup guide, architecture explanation, and report reference. |
| `.env.example` | Example environment variable file showing required configuration values for local and production use. |
| `.gitignore` | Excludes secrets, runtime data, uploads, generated PDFs, caches, logs, and virtual environments from version control. |
| `app.py` | Main Flask application. Contains API routes, authentication, session handling, validation, rate limiting, email functions, support requests, admin summary, file upload handling, downloads, and recovery routing. |
| `dev_server.py` | Local development entry point. Sets development defaults, ensures runtime directories exist, and runs Flask on `127.0.0.1:8000`. |
| `Dockerfile` | Container build definition. Installs system/Python dependencies and runs the app through Gunicorn. |
| `requirements.txt` | Python dependency list required by the application and tests. |
| `security.md` | Security-focused documentation for deployment, environment variables, migrations, rollback, and operational hardening. |
| `load-env.ps1` | PowerShell helper for loading environment variables from a local env file. |
| `start-dev.ps1` | PowerShell local development launcher. Sets development environment variables and starts the Flask server. |
| `start-dev.bat` | Windows batch launcher for local development. Useful when PowerShell script execution is restricted. |
| `start-server.bat` | Windows batch launcher intended for starting the server with configured environment values. |

### Frontend HTML Pages

| File | Usage |
| --- | --- |
| `login.html` | (removed) Login page was removed when the site was converted to a public-access workflow. |
| `signup.html` | (removed) Signup page was removed when the site was converted to a public-access workflow. |
| `index.html` | Main authenticated upload page. Allows users to select PDFs, enter a password, choose encryption mode, add recovery questions, and submit uploads. |
| `recovery.html` | Password recovery page. Uploads a recovery-enabled PDF, fetches embedded recovery questions, submits answers, and displays the recovered password when valid. |
| `support.html` | FAQ and contact page. Sends support/contact messages to `/api/support`. The frontend now avoids the `Unexpected token '<'` JSON error by using the shared API client fallback and JSON error handling. |
| `admin.html` | Admin dashboard page. Displays user counts, login activity, encryption counts, recovery counts, support query counts, recent logs, users, and support messages through `/api/admin/summary`. |
| `logout.html` | (removed) Logout page was removed when the site was converted to a public-access workflow. |

### Frontend CSS and JavaScript

| File | Usage |
| --- | --- |
| `assets/styles.css` | Main shared styling for layout, forms, cards, navigation, admin sections, support sections, responsive behavior, and common UI elements. |
| `assets/css/style.css` | Additional modern UI styling for the current frontend pages, including auth screens, support page, admin dashboard, and responsive adjustments. |
| `assets/app.js` | Shared UI behavior: mobile navigation toggle, password strength display, selected filename list, and recovery field visibility. |
| `assets/js/api-client.js` | Shared API fetch wrapper. Handles same-origin API calls, local Flask fallback at `http://127.0.0.1:8000`, explicit API base override through `LOCKITPDF_API_BASE`, JSON content-type checking, and clean errors when an HTML page is returned instead of JSON. |
| `assets/js/auth-guard.js` | Page guard (now no-op). Previously redirected unauthenticated users; it's been disabled so pages are public. |
| `assets/js/upload-client.js` | Upload form controller. Builds `FormData`, sends `/api/upload`, shows loading/errors, and redirects to the generated download URL. |

### Python Backend Package

| File | Usage |
| --- | --- |
| `backend/lockitpdf.py` | Core PDF encryption module. Validates password strength, encrypts PDFs with `pikepdf`, creates ZIP output for multiple files, embeds recovery metadata, and exposes a command-line interface. |
| `backend/recover_password.py` | Recovery module. Reads LockItPDF recovery payloads from encrypted PDFs, returns recovery questions, validates supplied answers, and returns the original password when answers match. |
| `backend/package_recovery.py` | Utility script for creating a recovery package ZIP containing an encrypted file, helper page, and README. It is supporting tooling rather than the main web workflow. |

### Tests

| File | Usage |
| --- | --- |
| `tests/test_security.py` | pytest test suite covering security and API behavior, including rate limits, authentication, admin authorization, upload/recovery behavior, and support-query visibility. |
| `tests/__pycache__/...` | Python-generated cache files created while running tests. These are not source files and should not be included in version control. |

### Runtime and Generated Folders

These folders are created by local execution, tests, uploads, and generated outputs. They are useful during development but should normally be excluded from version control and not treated as permanent source code.

| Folder/File Pattern | Usage |
| --- | --- |
| `runtime/` | Development runtime data folder used by Flask when `LOCKITPDF_DATA_DIR` points to the project runtime directory. |
| `runtime/users.json` | Local user account data for development/testing. Passwords are stored as hashes, not plaintext. |
| `runtime/sessions.json` | Server-side session records for active login cookies. |
| `runtime/tokens.json` | Email verification and password reset token records. |
| `runtime/events.json` | Application event log used for admin dashboard statistics and security auditing. |
| `runtime/jobs.json` | Job metadata for uploaded files and downloadable outputs. |
| `runtime/support.json` | Stored support/contact form messages. |
| `runtime/uploads/<job_id>/` | Temporary uploaded PDFs before processing. |
| `runtime/outputs/<job_id>/` | Generated encrypted PDFs or ZIP files ready for download. |
| `runtime_test/` | Test runtime folder and logs generated while running tests or development checks. |
| `storage/` | Older/local storage folder containing sessions, users, logs, and previous generated job files. It is runtime data, not core source code. |
| `storage/users/users.json` | Older/local user storage file from previous runs. |
| `storage/sessions/sess_*` | Generated session files from previous local execution. |
| `storage/logs/*.json` | Generated usage, auth, support, and system logs. |
| `storage/jobs/<job_id>/` | Previously uploaded or generated PDF job files. |
| `__pycache__/` | Python bytecode cache generated automatically. |
| `backend/__pycache__/` | Python bytecode cache for backend modules. |
| `.pytest_cache/` | pytest cache folder generated after test runs. |

For a thesis or research paper, describe runtime data as temporary/generated operational data. Do not include personal uploaded PDFs, session files, logs, or cache files as part of the permanent implementation.

## API Endpoints

All API responses are JSON. Missing or wrong-method `/api/*` routes return JSON errors so the frontend does not try to parse an HTML document as JSON.

### Health Check

```txt
GET /api/health
```

Returns service status:

```json
{
  "ok": true,
  "service": "lockitpdf-api"
}
```

### Signup

```txt
POST /api/signup
```

Accepts JSON or form data:

```json
{
  "username": "demo",
  "email": "demo@example.com",
  "password": "Strong1!"
}
```

Creates a user, hashes the password with Argon2, optionally sends email verification, creates a session, and sets an HttpOnly cookie.

### Login

```txt
POST /api/login
```

Accepts:

```json
{
  "username": "demo@example.com",
  "password": "Strong1!"
}
```

Returns the authenticated user and sets the session cookie.

### Current User

```txt
GET /api/me
```

Returns the current authenticated user when the session cookie is valid.

### Logout

```txt
POST /api/logout
```

Invalidates the server-side session and deletes the `lockitpdf_session` cookie.

### Email Verification

```txt
GET /api/verify-email?token=<token>
```

Consumes an email verification token and marks the user email as verified.

### Password Reset Request

```txt
POST /api/password-reset/request
```

Accepts an email address and sends a password reset link when the account exists. The response is intentionally generic to avoid account enumeration.

### Password Reset Confirm

```txt
POST /api/password-reset/confirm
```

Accepts a reset token and new password, updates the password hash, clears failed-login state, and invalidates active sessions for that user.

### Support Contact

```txt
POST /api/support
```

Accepts:

```json
{
  "name": "Visitor",
  "email": "visitor@example.com",
  "message": "Please help with uploads."
}
```

Stores the support query in `runtime/support.json`, logs a privacy-preserving event with an email hash, and sends the message to the configured admin email when SMTP/admin email are configured.

### PDF Upload and Encryption

```txt
POST /api/upload
```

Requires authentication. Accepts multipart form data:

```txt
pdfs[]      one or more PDF files
password    strong encryption password
mode        regular | recovery
question[]  recovery questions, required only for recovery mode
answer[]    recovery answers, required only for recovery mode
```

Returns:

```json
{
  "ok": true,
  "job_id": "abc123",
  "filename": "protected_file.pdf",
  "download_url": "/downloads/abc123/protected_file.pdf"
}
```

### Download

```txt
GET /downloads/<job_id>/<filename>
```

Requires authentication. Sends the generated encrypted PDF or ZIP as an attachment. The API verifies that the current user owns the job before serving the file.

### Recover Password

```txt
POST /api/recover
```

Requires authentication. Accepts a recovery-enabled PDF. If answers are not supplied, it returns the recovery questions. If answers are supplied, it validates them and returns the recovered password.

### Admin Summary

```txt
GET /api/admin/summary
```

Requires an admin user. Returns users, recent logs, support queries, and dashboard statistics.

## Security Design

### Password Rules

User passwords and PDF encryption passwords must include:

- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one symbol

Example:

```txt
LockItPDF1!
```

### Account Security

- Passwords are hashed using Argon2 through `argon2-cffi`.
- Older Werkzeug hashes can be migrated after successful login.
- Sessions are stored server-side.
- Browser cookies are HttpOnly and `SameSite=Strict`.
- Production cookies should be `Secure`.
- Failed logins are counted.
- Accounts can be temporarily locked after repeated failures.
- Suspicious activity can require CAPTCHA depending on configuration.

### API Security

- Flask-Limiter rate limits sensitive endpoints.
- Uploads are size-limited through `LOCKITPDF_MAX_UPLOAD_MB`.
- Only PDF file extensions are accepted for upload.
- Download routes validate job ownership.
- API routes return JSON errors for 404 and 405 cases.
- Production mode enforces HTTPS through forwarded protocol checks.
- Security headers include `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- HSTS is enabled in production.

### PDF Security

Regular mode encrypts the PDF with the supplied password and does not store recovery data.

Recovery mode encrypts the PDF and embeds a LockItPDF recovery payload. The payload stores recovery questions, hashes of normalized answers, and the password in an encoded recovery structure so the LockItPDF recovery workflow can retrieve it after correct answers.

Important research/report note: recovery-enabled PDFs must be treated as sensitive. Anyone with the PDF and the correct recovery answers can recover the password.

## Encryption Modes

### Regular Encryption

Regular mode is suitable when the user wants standard PDF password protection and does not need password recovery.

Characteristics:

- Strong password required.
- PDF is encrypted through `pikepdf`.
- Multiple PDFs are returned as a ZIP.
- Password cannot be recovered by LockItPDF if forgotten.

### Recovery Encryption

Recovery mode is suitable when a user wants a controlled recovery mechanism.

Characteristics:

- Strong password required.
- At least one recovery question and answer is required.
- Recovery data is embedded into the generated PDF.
- Recovery happens through `recovery.html` and `/api/recover`.
- PDF readers still show their normal password prompt; they do not show a custom LockItPDF recovery button.

## Important Recovery Limitation

PDF readers such as Chrome, Edge, Adobe Reader, Android viewers, and iOS Files control their own password prompt. A web application cannot add a custom "Forgot Password" button inside that native PDF-reader prompt.

Therefore, LockItPDF recovery is implemented as a separate web workflow:

1. User opens `recovery.html`.
2. User uploads the recovery-enabled PDF.
3. LockItPDF reads the embedded recovery questions.
4. User answers the questions.
5. LockItPDF returns the password if the answers match.

## Local Installation

From the project root:

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
.\start-dev.ps1
```

If PowerShell script execution is blocked, use:

```bat
start-dev.bat
```

Open:

```txt
http://127.0.0.1:8000/
```

The app should be opened through the Flask server on port `8000`. If pages are opened through an old XAMPP static URL, API calls may hit the wrong server. The shared API client now retries the local Flask backend and shows a clean error if HTML is returned instead of JSON.

## Docker Installation

Build:

```bash
docker build -t lockitpdf .
```

Run:

```bash
docker run -p 8000:8000 lockitpdf
```

Open:

```txt
http://127.0.0.1:8000/
```

## Environment Variables

Important variables include:

| Variable | Purpose |
| --- | --- |
| `ENV` | `development` or `production`. |
| `SESSION_SECRET` | Secret used for session token signing. Required in production. |
| `COOKIE_SECURE` | Enables secure cookies in production. |
| `FRONTEND_ORIGIN` | Main frontend origin used for CORS and links. |
| `FRONTEND_ORIGINS` | Comma-separated allowed frontend origins. |
| `APP_BASE_URL` | Base URL used in verification and password reset emails. |
| `LOCKITPDF_DATA_DIR` | Private runtime data folder for users, sessions, uploads, outputs, tokens, logs, and support queries. |
| `LOCKITPDF_ADMIN_EMAIL` | Admin email address. Also determines admin role and receives support messages when SMTP is configured. |
| `LOCKITPDF_SESSION_TTL` | Session lifetime in seconds. |
| `LOCKITPDF_TOKEN_TTL` | Verification/reset token lifetime in seconds. |
| `LOCKITPDF_JOB_TTL` | Upload/output cleanup age in seconds. |
| `LOCKITPDF_MAX_UPLOAD_MB` | Maximum upload size in megabytes. |
| `RATELIMIT_STORAGE_URI` | Rate-limit storage backend. Use Redis or another shared store in production. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` | SMTP configuration for verification, reset, and support emails. |

See `.env.example` and `security.md` for more deployment detail.

## Testing

Run the test suite:

```bash
python -m pytest tests\test_security.py
```

Current verification performed after the latest support/contact fix:

```txt
10 passed
```

The tests cover important security and API behaviors, including authenticated access, admin authorization, rate-limit JSON responses, support query storage, and dashboard visibility.

## Recent Support/Contact Fix

The contact/support form previously could fail with:

```txt
Unexpected token '<', "<!doctype "... is not valid JSON
```

This happened when the browser received an HTML page from the wrong server or route and then tried to parse it as JSON.

The fix includes:

- `assets/js/api-client.js` checks whether API responses are JSON.
- Local development calls can fall back to `http://127.0.0.1:8000`.
- HTML API responses are converted into clean JSON error responses for the page.
- `app.py` now returns JSON for missing or wrong-method `/api/*` routes.

## Methodology for Report or Thesis

You can describe the implementation methodology as:

1. Requirement analysis: identify the need for PDF encryption and optional recovery.
2. System design: split the application into frontend, API, PDF-processing backend, and runtime storage.
3. Authentication design: use hashed passwords and server-side sessions.
4. PDF encryption design: use `pikepdf` for PDF encryption and output generation.
5. Recovery design: embed a LockItPDF recovery payload and validate answers during recovery.
6. Security design: add password rules, rate limiting, session cookies, HTTPS enforcement, and upload validation.
7. Testing: use pytest to validate core API and security behavior.
8. Deployment planning: support local development, Docker, and production environment variables.

## Suggested Report Sections

- Introduction
- Problem Statement
- Objectives
- Scope of the Project
- Literature/Technology Review
- Existing System and Limitations
- Proposed System
- System Architecture
- Module Description
- Database/Storage Design
- API Design
- Security Design
- Implementation Details
- Testing and Validation
- Results and Screenshots
- Limitations
- Future Enhancements
- Conclusion

## Limitations

- Local JSON files are used for development storage; production should use a database or managed storage.
- Server-side sessions are stored in JSON files locally; production scaling should use Redis or database-backed sessions.
- Recovery mode intentionally embeds recovery information in the PDF, so recovery-enabled files must be protected carefully.
- Uploaded files and generated outputs are stored locally and cleaned up by TTL; production deployments need persistent private storage.
- Email delivery depends on external SMTP configuration.
- The application does not modify the native password prompt shown by PDF readers.

## Future Scope

- Move users, jobs, sessions, and support queries to PostgreSQL or MySQL.
- Use Redis for production session and rate-limit storage.
- Add CSRF protection for browser form flows.
- Add malware scanning for uploaded PDFs.
- Add stronger audit log search and export features for admins.
- Add file-size limits at the reverse-proxy/web-server level.
- Add encrypted private object storage for uploads and outputs.
- Add two-factor authentication for admin accounts.
- Improve recovery mode with stronger cryptographic protection for embedded recovery data.
- Add automated CI testing and deployment pipelines.

## Conclusion

LockItPDF is a complete educational and practical implementation of a secure PDF encryption web application. It demonstrates frontend form handling, Flask API design, authentication, password hashing, session security, PDF encryption, optional recovery workflows, support-query handling, admin reporting, testing, and deployment preparation. The project is suitable for academic reports, thesis discussion, and further research into secure document-management systems.
