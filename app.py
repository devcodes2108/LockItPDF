import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import smtplib
import tempfile
import time
import uuid
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from flask import Flask, jsonify, redirect, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email_validator import EmailNotValidError, validate_email
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from backend.lockitpdf import (
    encrypt_pdfs_regular,
    encrypt_pdfs_with_recovery,
    is_strong_password,
)
from backend.recover_password import questions as recovery_questions
from backend.recover_password import recover as recover_password_from_pdf


BASE_DIR = Path(__file__).resolve().parent
ENV = os.environ.get("ENV", "development").lower()
DEFAULT_DATA_DIR = BASE_DIR / "runtime" if ENV != "production" else Path(tempfile.gettempdir()) / "lockitpdf_runtime"
DATA_DIR = Path(os.environ.get("LOCKITPDF_DATA_DIR", DEFAULT_DATA_DIR))
UPLOAD_DIR = DATA_DIR / "uploads"
OUTPUT_DIR = DATA_DIR / "outputs"
USERS_FILE = DATA_DIR / "users.json"
EVENTS_FILE = DATA_DIR / "events.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"
TOKENS_FILE = DATA_DIR / "tokens.json"
JOBS_FILE = DATA_DIR / "jobs.json"
SUPPORT_FILE = DATA_DIR / "support.json"

ADMIN_EMAIL = os.environ.get("LOCKITPDF_ADMIN_EMAIL", "").strip().lower()
DEFAULT_DEV_ORIGINS = "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1,http://localhost"
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://127.0.0.1:8000")
FRONTEND_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("FRONTEND_ORIGINS", FRONTEND_ORIGIN if ENV == "production" else DEFAULT_DEV_ORIGINS).split(",")
    if origin.strip()
]
APP_BASE_URL = os.environ.get("APP_BASE_URL", FRONTEND_ORIGIN)
SESSION_SECRET = os.environ.get("SESSION_SECRET") or os.environ.get("JWT_SECRET") or ("dev-session-secret" if os.environ.get("ENV", "development").lower() != "production" else "")
SESSION_TTL_SECONDS = int(os.environ.get("LOCKITPDF_SESSION_TTL", "2592000"))
TOKEN_TTL_SECONDS = int(os.environ.get("LOCKITPDF_TOKEN_TTL", "3600"))
JOB_TTL_SECONDS = int(os.environ.get("LOCKITPDF_JOB_TTL", "604800"))
MAX_UPLOAD_BYTES = int(os.environ.get("LOCKITPDF_MAX_UPLOAD_MB", "20")) * 1024 * 1024
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true" if ENV == "production" else "false").lower() == "true"
FAILED_LOGIN_LIMIT = int(os.environ.get("LOCKITPDF_FAILED_LOGIN_LIMIT", "5"))
LOCKOUT_SECONDS = int(os.environ.get("LOCKITPDF_LOCKOUT_SECONDS", "900"))
CAPTCHA_FAILURE_THRESHOLD = int(os.environ.get("LOCKITPDF_CAPTCHA_FAILURE_THRESHOLD", "3"))
ALERT_WEBHOOK_URL = os.environ.get("LOCKITPDF_ALERT_WEBHOOK_URL", "")
REQUIRE_EMAIL_VERIFICATION = os.environ.get("REQUIRE_EMAIL_VERIFICATION", "false").lower() == "true"

if ENV == "production" and (not SESSION_SECRET or SESSION_SECRET == "dev-session-secret"):
    raise RuntimeError("SESSION_SECRET must be set to a high-entropy value in production.")
if ENV == "production" and not os.environ.get("LOCKITPDF_DATA_DIR"):
    raise RuntimeError("LOCKITPDF_DATA_DIR must point to private runtime storage in production.")
if ENV == "production" and not ADMIN_EMAIL:
    raise RuntimeError("LOCKITPDF_ADMIN_EMAIL must be set in production.")

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

app = Flask(__name__, static_folder=".", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
CORS(app, origins=FRONTEND_ORIGINS, supports_credentials=True)
limiter = Limiter(get_remote_address, app=app, storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))


class ValidationProblem(ValueError):
    pass


class StrictPayload:
    @classmethod
    def model_validate(cls, payload):
        return cls(payload)


class SignupSchema(StrictPayload):
    def __init__(self, payload):
        self.username = clean_string(payload.get("username"), "username", 3, 64)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.username):
            raise ValidationProblem("Username may contain only letters, numbers, dots, underscores, and hyphens.")
        self.email = clean_email(payload.get("email"))
        self.password = clean_string(payload.get("password"), "password", 8, 256)
        if not is_strong_password(self.password):
            raise ValidationProblem("Use at least 8 characters with uppercase, lowercase, number, and symbol.")


class LoginSchema(StrictPayload):
    def __init__(self, payload):
        self.username = clean_string(payload.get("username"), "username", 1, 254)
        self.password = clean_string(payload.get("password"), "password", 1, 256)


class ResetRequestSchema(StrictPayload):
    def __init__(self, payload):
        self.email = clean_email(payload.get("email"))
        self.captcha_token = optional_string(payload.get("captcha_token"), 1024)


class ResetConfirmSchema(StrictPayload):
    def __init__(self, payload):
        self.token = clean_string(payload.get("token"), "token", 32, 512)
        self.password = clean_string(payload.get("password"), "password", 8, 256)
        if not is_strong_password(self.password):
            raise ValidationProblem("Use at least 8 characters with uppercase, lowercase, number, and symbol.")


class SupportSchema(StrictPayload):
    def __init__(self, payload):
        self.name = clean_string(payload.get("name"), "name", 1, 120)
        self.email = clean_email(payload.get("email"))
        self.message = clean_string(payload.get("message"), "message", 5, 2000)


def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        DATA_DIR.chmod(0o700)
    except OSError:
        pass
    for folder in (UPLOAD_DIR, OUTPUT_DIR):
        folder.mkdir(parents=True, exist_ok=True)
    # Keep runtime files outside the web root by default to reduce direct download risk.
    for path in (USERS_FILE, EVENTS_FILE, SESSIONS_FILE, TOKENS_FILE, JOBS_FILE, SUPPORT_FILE):
        if not path.exists():
            path.write_text("[]" if path != JOBS_FILE else "{}", encoding="utf-8")


def read_json(path, fallback):
    ensure_dirs()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return fallback


def write_json(path, data):
    ensure_dirs()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_users():
    return read_json(USERS_FILE, [])


def write_users(users):
    write_json(USERS_FILE, users)


def read_events():
    return read_json(EVENTS_FILE, [])


def read_sessions():
    return read_json(SESSIONS_FILE, [])


def write_sessions(sessions):
    write_json(SESSIONS_FILE, sessions[-5000:])


def read_tokens():
    return read_json(TOKENS_FILE, [])


def write_tokens(tokens):
    write_json(TOKENS_FILE, tokens[-5000:])


def read_jobs():
    return read_json(JOBS_FILE, {})


def write_jobs(jobs):
    write_json(JOBS_FILE, jobs)


def read_support():
    return read_json(SUPPORT_FILE, [])


def write_support(items):
    write_json(SUPPORT_FILE, items[-1000:])


def log_event(event_type, user_id=None, **details):
    safe_details = {k: v for k, v in details.items() if "token" not in k.lower() and "password" not in k.lower()}
    events = read_events()
    events.append({"id": uuid.uuid4().hex, "type": event_type, "user_id": user_id, "created_at": int(time.time()), **safe_details})
    write_json(EVENTS_FILE, events[-1000:])
    if event_type in {"account_locked", "rate_limit", "admin_action", "suspicious_activity"}:
        send_alert(event_type, user_id=user_id, **safe_details)


def send_alert(event_type, **details):
    if not ALERT_WEBHOOK_URL:
        return
    # Alert payloads intentionally omit secrets and raw tokens before leaving the app.
    payload = json.dumps({"event": event_type, "details": details, "created_at": int(time.time())}).encode("utf-8")
    try:
        request_obj = Request(ALERT_WEBHOOK_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request_obj, timeout=2):
            pass
        log_event("alert_sent", alert_type=event_type, detail_keys=sorted(details.keys()))
    except OSError:
        log_event("alert_failed", alert_type=event_type, detail_keys=sorted(details.keys()))


def error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


@app.errorhandler(429)
def rate_limit_error(exc):
    log_event("rate_limit", path=request.path, remote_hash=hashlib.sha256(get_remote_address().encode()).hexdigest())
    return error("Too many requests. Try again later.", 429)


@app.errorhandler(404)
def not_found_error(exc):
    if request.path.startswith("/api/"):
        return error("API endpoint not found.", 404)
    return exc


@app.errorhandler(405)
def method_not_allowed_error(exc):
    if request.path.startswith("/api/"):
        return error("Method not allowed for this API endpoint.", 405)
    return exc


def clean_string(value, field, min_length, max_length):
    if not isinstance(value, str):
        raise ValidationProblem(f"{field} is required.")
    value = value.strip()
    if len(value) < min_length or len(value) > max_length:
        raise ValidationProblem(f"{field} length is invalid.")
    return value


def optional_string(value, max_length):
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > max_length:
        raise ValidationProblem("Optional field length is invalid.")
    return value


def clean_email(value):
    try:
        # email-validator provides robust syntax and normalization checks.
        return validate_email(clean_string(value, "email", 3, 254), check_deliverability=False).normalized.lower()
    except (EmailNotValidError, ValidationProblem) as exc:
        raise ValidationProblem("Enter a valid email address.") from exc


def parse_payload(schema):
    try:
        payload = request.get_json(silent=True) if request.is_json else request.form.to_dict(flat=True)
        return schema.model_validate(payload or {}), None
    except ValidationProblem as exc:
        return None, error(str(exc), 400)


def hash_password(password):
    return ph.hash(password)


def verify_password(user, password):
    stored = user.get("password_hash", "")
    try:
        if stored.startswith("$argon2"):
            ok = ph.verify(stored, password)
            return ok, ph.check_needs_rehash(stored)
        # Migration path: verify legacy Werkzeug/PHP-style hashes, then rehash on success.
        ok = check_password_hash(stored, password)
        return ok, ok
    except (VerifyMismatchError, VerificationError, ValueError):
        return False, False


def public_user(user):
    return {"id": user["id"], "username": user["username"], "email": user["email"], "role": user.get("role", "user"), "email_verified": account_email_verified(user)}


def public_support(item):
    return {
        "id": item.get("id"),
        "name": item.get("name", ""),
        "email": item.get("email", ""),
        "message": item.get("message", ""),
        "created_at": item.get("created_at", 0),
        "user_id": item.get("user_id"),
    }


def account_email_verified(user):
    # Legacy accounts created before email verification remain usable during migration.
    return bool(user.get("email_verified", True))


def configured_admin_email():
    if ADMIN_EMAIL:
        return ADMIN_EMAIL
    # Development fallback preserves existing local admin accounts without hardcoding PII.
    if ENV != "production":
        for user in read_users():
            if user.get("role") == "admin" and user.get("email"):
                return user["email"].strip().lower()
    return ""


def role_for_email(email):
    return "admin" if configured_admin_email() and email.strip().lower() == configured_admin_email() else "user"


def token_hash(token):
    # HMAC token hashes keep stolen token stores from becoming bearer-token stores.
    return hmac.new(SESSION_SECRET.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def set_session_cookie(response, token):
    # HttpOnly prevents JavaScript token theft; SameSite Strict reduces CSRF exposure.
    response.set_cookie("lockitpdf_session", token, max_age=SESSION_TTL_SECONDS, httponly=True, secure=COOKIE_SECURE, samesite="Strict", path="/")


def create_session(user_id):
    raw_token = secrets.token_urlsafe(32)
    sessions = [s for s in read_sessions() if s.get("expires_at", 0) > time.time()]
    sessions.append({"token_hash": token_hash(raw_token), "user_id": user_id, "expires_at": int(time.time() + SESSION_TTL_SECONDS)})
    write_sessions(sessions)
    return raw_token


def invalidate_session(raw_token):
    if not raw_token:
        return
    hashed = token_hash(raw_token)
    write_sessions([s for s in read_sessions() if s.get("token_hash") != hashed])


def invalidate_user_sessions(user_id):
    # Password resets and privilege changes invalidate old session identifiers.
    write_sessions([s for s in read_sessions() if s.get("user_id") != user_id])


def auth_token():
    return request.cookies.get("lockitpdf_session", "")


def sync_admin_role(user):
    expected = role_for_email(user.get("email", ""))
    if user.get("role") == expected:
        return user
    users = read_users()
    for account in users:
        if account["id"] == user["id"]:
            account["role"] = expected
            user["role"] = expected
            invalidate_user_sessions(user["id"])
            break
    write_users(users)
    log_event("admin_action", user_id=user["id"], action="role_rotated", role=expected)
    return user


def current_user():
    raw = auth_token()
    if not raw:
        return None
    hashed = token_hash(raw)
    now = time.time()
    sessions = [s for s in read_sessions() if s.get("expires_at", 0) > now]
    write_sessions(sessions)
    session = next((s for s in sessions if s.get("token_hash") == hashed), None)
    if not session:
        return None
    user = next((u for u in read_users() if u["id"] == session["user_id"]), None)
    return sync_admin_role(user) if user else None


def require_user():
    user = current_user()
    if not user:
        return None, error("Not authenticated.", 401)
    return user, None


def require_admin_user():
    user, failure = require_user()
    if failure:
        return None, failure
    if user.get("role") != "admin" or user.get("email", "").lower() != configured_admin_email():
        return None, error("Admin access required.", 403)
    return user, None


def token_record(user_id, purpose):
    raw = secrets.token_urlsafe(48)
    record = {"token_hash": token_hash(raw), "user_id": user_id, "purpose": purpose, "expires_at": int(time.time() + TOKEN_TTL_SECONDS), "used": False}
    tokens = read_tokens()
    tokens.append(record)
    write_tokens(tokens)
    return raw


def consume_token(raw, purpose):
    if not raw:
        return None
    hashed = token_hash(raw)
    tokens = read_tokens()
    now = time.time()
    matched = None
    for record in tokens:
        if record.get("token_hash") == hashed and record.get("purpose") == purpose and not record.get("used") and record.get("expires_at", 0) > now:
            record["used"] = True
            matched = record
            break
    write_tokens(tokens)
    return matched


def send_email(to, subject, body):
    host = os.environ.get("SMTP_HOST")
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    sender = os.environ.get("SMTP_FROM", user or "no-reply@lockitpdf.local")
    if not host or not user or not password:
        log_event("email_skipped", reason="smtp_not_configured", recipient_hash=hashlib.sha256(to.encode()).hexdigest())
        return False
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP_SSL(host, int(os.environ.get("SMTP_PORT", "465"))) as smtp:
        smtp.login(user, password)
        smtp.send_message(msg)
    return True


def send_verification(user):
    raw = token_record(user["id"], "verify_email")
    link = f"{APP_BASE_URL}/api/verify-email?token={raw}"
    # Only one-time links are emailed; raw tokens are never logged.
    send_email(user["email"], "Verify your LockItPDF email", f"Verify your email within 1 hour:\n\n{link}\n")


def failed_login_state(identifier):
    users = read_users()
    return next((u for u in users if identifier in (u["username"].lower(), u["email"].lower())), None)


def retry_after_seconds(user):
    count = int(user.get("failed_login_count", 0)) if user else 0
    return min(LOCKOUT_SECONDS, 2 ** max(0, count - 1))


def suspicious_activity(user=None):
    return bool(user and int(user.get("failed_login_count", 0)) >= CAPTCHA_FAILURE_THRESHOLD)


def verify_captcha(captcha_token):
    if not os.environ.get("LOCKITPDF_CAPTCHA_SECRET"):
        return True
    # A real deployment should verify the token with the CAPTCHA provider server-side.
    return bool(captcha_token and len(captcha_token) >= 20)


def register_failed_login(user):
    if not user:
        return
    now = int(time.time())
    user["failed_login_count"] = int(user.get("failed_login_count", 0)) + 1
    user["last_failed_login_at"] = now
    if user["failed_login_count"] >= FAILED_LOGIN_LIMIT:
        user["locked_until"] = now + LOCKOUT_SECONDS
        log_event("account_locked", user_id=user["id"])
    users = read_users()
    for account in users:
        if account["id"] == user["id"]:
            account.update(user)
            break
    write_users(users)


def reset_failed_logins(user):
    users = read_users()
    for account in users:
        if account["id"] == user["id"]:
            account["failed_login_count"] = 0
            account["locked_until"] = 0
            user.update(account)
            break
    write_users(users)


def safe_upload_name(uploaded):
    suffix = Path(secure_filename(uploaded.filename)).suffix.lower()
    return f"{uuid.uuid4().hex}{suffix}"


def validate_pdf_upload(uploaded):
    if not uploaded or uploaded.filename == "":
        raise ValueError("Upload at least one PDF file.")
    original = secure_filename(uploaded.filename)
    if not original or len(original) > 180 or not original.lower().endswith(".pdf"):
        raise ValueError("Only PDF files are allowed.")
    stream = uploaded.stream
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    if size <= 0 or size > MAX_UPLOAD_BYTES:
        raise ValueError("PDF file is empty or exceeds the upload size limit.")
    if stream.read(5) != b"%PDF-":
        raise ValueError("Uploaded file is not a valid PDF.")
    stream.seek(0)
    mime = uploaded.mimetype or mimetypes.guess_type(original)[0] or ""
    if mime not in ("application/pdf", "application/octet-stream"):
        raise ValueError("Uploaded file must be a PDF.")
    if ENV == "production" and not os.environ.get("LOCKITPDF_AV_SCANNER"):
        log_event("upload_manual_review", reason="av_scanner_not_configured")
    # Production deployments should add antivirus scanning here before processing.
    return original


def same_origin_url(url):
    allowed = urlparse(FRONTEND_ORIGIN)
    candidate = urlparse(url)
    return candidate.scheme == allowed.scheme and candidate.netloc == allowed.netloc


def save_uploads(files, owner_id):
    job_id = uuid.uuid4().hex
    job_upload_dir = UPLOAD_DIR / job_id
    job_output_dir = OUTPUT_DIR / job_id
    job_upload_dir.mkdir(parents=True, exist_ok=True)
    job_output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    originals = []
    for uploaded in files:
        original = validate_pdf_upload(uploaded)
        target = job_upload_dir / safe_upload_name(uploaded)
        uploaded.save(target)
        paths.append(str(target))
        originals.append(original)
    if not paths:
        raise ValueError("Upload at least one PDF file.")
    jobs = read_jobs()
    jobs[job_id] = {"owner_id": owner_id, "created_at": int(time.time()), "uploads": originals, "outputs": []}
    write_jobs(jobs)
    return job_id, paths, job_output_dir


def cleanup_old_jobs():
    now = time.time()
    jobs = read_jobs()
    for job_id, job in list(jobs.items()):
        if now - int(job.get("created_at", 0)) >= JOB_TTL_SECONDS:
            shutil.rmtree(UPLOAD_DIR / job_id, ignore_errors=True)
            shutil.rmtree(OUTPUT_DIR / job_id, ignore_errors=True)
            jobs.pop(job_id, None)
    write_jobs(jobs)


def assert_job_owner(job_id, user):
    jobs = read_jobs()
    job = jobs.get(job_id)
    if not job or job.get("owner_id") != user["id"]:
        return None
    return job


def parse_recovery_data():
    questions = request.form.getlist("question[]") or request.form.getlist("question")
    answers = request.form.getlist("answer[]") or request.form.getlist("answer")
    recovery = []
    for index, question in enumerate(questions):
        question = str(question or "").strip()[:160]
        answer = str(answers[index] if index < len(answers) else "").strip()[:256]
        if question and answer:
            recovery.append({"question": question, "answer": answer})
    return recovery


def is_dev_origin_allowed(origin):
    if ENV == "production" or not origin:
        return False
    if origin == "null":
        return True
    parsed = urlparse(origin)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https"):
        return False
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    if hostname.startswith("192.168.") or hostname.startswith("10."):
        return True
    if hostname.startswith("172."):
        parts = hostname.split(".")
        return len(parts) == 4 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31
    return False


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    origin = request.headers.get("Origin")
    if is_dev_origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = request.headers.get("Access-Control-Request-Headers", "Content-Type")
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers.add("Vary", "Origin")
    if ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.before_request
def enforce_https():
    if ENV != "production":
        return None
    if request.headers.get("X-Forwarded-Proto", request.scheme) != "https":
        # Redirecting cleartext requests protects cookies that require Secure transport.
        return redirect(request.url.replace("http://", "https://", 1), code=308)
    return None


@app.get("/")
def index():
    if not current_user():
        return redirect("/login.html")
    return app.send_static_file("index.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "lockitpdf-api"})


@app.post("/api/signup")
@limiter.limit("5 per hour")
def signup():
    cleanup_old_jobs()
    data, failure = parse_payload(SignupSchema)
    if failure:
        return failure
    if os.environ.get("LOCKITPDF_CAPTCHA_ON_SIGNUP", "false").lower() == "true" and not verify_captcha(request.form.get("captcha_token") or (request.get_json(silent=True) or {}).get("captcha_token")):
        log_event("suspicious_activity", reason="captcha_required", path="/api/signup")
        return error("Complete CAPTCHA to continue.", 403)
    email = data.email.lower()
    users = read_users()
    if any(u["username"].lower() == data.username.lower() or u["email"].lower() == email for u in users):
        return error("That username or email is already registered.", 409)
    user = {"id": uuid.uuid4().hex, "username": data.username, "email": email, "password_hash": hash_password(data.password), "role": role_for_email(email), "email_verified": False, "created_at": int(time.time())}
    users.append(user)
    write_users(users)
    send_verification(user)
    log_event("signup", user_id=user["id"], role=user["role"])
    token = create_session(user["id"])
    response = jsonify({"ok": True, "user": public_user(user), "verification_required": REQUIRE_EMAIL_VERIFICATION})
    set_session_cookie(response, token)
    return response, 201


@app.get("/api/verify-email")
def verify_email():
    record = consume_token(request.args.get("token", ""), "verify_email")
    if not record:
        return error("Verification link is invalid or expired.", 400)
    users = read_users()
    for user in users:
        if user["id"] == record["user_id"]:
            user["email_verified"] = True
            log_event("email_verified", user_id=user["id"])
            break
    write_users(users)
    return jsonify({"ok": True, "message": "Email verified."})


@app.post("/api/login")
@limiter.limit("10 per minute")
def login():
    cleanup_old_jobs()
    data, failure = parse_payload(LoginSchema)
    if failure:
        return failure
    identifier = data.username.strip().lower()
    user = failed_login_state(identifier)
    if user and int(user.get("locked_until", 0)) > time.time():
        log_event("login_blocked", user_id=user["id"])
        response, status = error("Account temporarily locked. Try again later.", 423)
        response.headers["Retry-After"] = str(max(1, int(user.get("locked_until", 0) - time.time())))
        return response, status
    for account in read_users():
        if identifier in (account["username"].lower(), account["email"].lower()):
            ok, needs_rehash = verify_password(account, data.password)
            if not ok:
                register_failed_login(account)
                delay = retry_after_seconds(account)
                log_event("login_failed", user_id=account["id"], backoff_seconds=delay)
                response, status = error("Invalid username/email or password.", 401)
                response.headers["Retry-After"] = str(delay)
                if suspicious_activity(account):
                    log_event("suspicious_activity", user_id=account["id"], reason="failed_login_threshold")
                return response, status
            account = sync_admin_role(account)
            if REQUIRE_EMAIL_VERIFICATION and not account_email_verified(account):
                return error("Verify your email before logging in.", 403)
            if needs_rehash:
                users = read_users()
                for stored in users:
                    if stored["id"] == account["id"]:
                        stored["password_hash"] = hash_password(data.password)
                        break
                write_users(users)
            reset_failed_logins(account)
            token = create_session(account["id"])
            log_event("login_success", user_id=account["id"], role=account.get("role", "user"))
            response = jsonify({"ok": True, "user": public_user(account)})
            set_session_cookie(response, token)
            return response
    log_event("login_failed")
    return error("Invalid username/email or password.", 401)


@app.get("/api/me")
def me():
    user = current_user()
    if not user:
        return error("Not authenticated.", 401)
    return jsonify({"ok": True, "user": public_user(user)})


@app.post("/api/logout")
def logout():
    user = current_user()
    invalidate_session(auth_token())
    log_event("logout", user_id=user["id"] if user else None)
    response = jsonify({"ok": True})
    response.delete_cookie("lockitpdf_session", path="/")
    return response


@app.post("/api/password-reset/request")
@limiter.limit("5 per hour")
def password_reset_request():
    data, failure = parse_payload(ResetRequestSchema)
    if failure:
        return failure
    user = next((u for u in read_users() if u["email"].lower() == data.email.lower()), None)
    if user and suspicious_activity(user) and not verify_captcha(data.captcha_token):
        log_event("suspicious_activity", user_id=user["id"], reason="captcha_required_reset")
        return error("Complete CAPTCHA to continue.", 403)
    if user:
        raw = token_record(user["id"], "password_reset")
        link = f"{APP_BASE_URL}/reset.html?token={raw}"
        send_email(user["email"], "Reset your LockItPDF password", f"Reset your password within 1 hour:\n\n{link}\n")
        log_event("password_reset_requested", user_id=user["id"])
    return jsonify({"ok": True, "message": "If that email exists, a reset link has been sent."})


@app.post("/api/password-reset/confirm")
@limiter.limit("5 per hour")
def password_reset_confirm():
    data, failure = parse_payload(ResetConfirmSchema)
    if failure:
        return failure
    record = consume_token(data.token, "password_reset")
    if not record:
        return error("Reset token is invalid or expired.", 400)
    users = read_users()
    for user in users:
        if user["id"] == record["user_id"]:
            user["password_hash"] = hash_password(data.password)
            user["failed_login_count"] = 0
            user["locked_until"] = 0
            invalidate_user_sessions(user["id"])
            log_event("password_reset_completed", user_id=user["id"])
            break
    write_users(users)
    return jsonify({"ok": True})


@app.post("/api/support")
@limiter.limit("10 per hour")
def support_request():
    data, failure = parse_payload(SupportSchema)
    if failure:
        return failure
    user = current_user()
    item = {
        "id": uuid.uuid4().hex,
        "name": data.name,
        "email": data.email,
        "message": data.message,
        "user_id": user["id"] if user else None,
        "created_at": int(time.time()),
    }
    support_items = read_support()
    support_items.append(item)
    write_support(support_items)
    log_event("support_query", user_id=item["user_id"], email_hash=hashlib.sha256(data.email.encode()).hexdigest())
    admin_email = configured_admin_email()
    if admin_email:
        # Only the admin email receives the support body; logs keep only hashes.
        send_email(admin_email, "New LockItPDF support query", f"Name: {data.name}\nEmail: {data.email}\n\n{data.message}\n")
    return jsonify({"ok": True, "message": "Your query has been sent."}), 201


@app.post("/api/upload")
@limiter.limit("20 per hour")
def upload():
    cleanup_old_jobs()
    user, failure = require_user()
    if failure:
        return failure
    password = request.form.get("encryption_password", "") or request.form.get("password", "")
    mode = request.form.get("mode", "regular")
    if mode not in ("regular", "recovery"):
        return error("Choose a valid encryption mode.")
    if not is_strong_password(password):
        return error("Use at least 8 characters with uppercase, lowercase, number, and symbol.")
    try:
        files = request.files.getlist("pdfs[]") or request.files.getlist("pdfs")
        job_id, paths, output_dir = save_uploads(files, user["id"])
        is_zip = len(paths) > 1
        filename = "encrypted_pdfs_with_recovery.zip" if mode == "recovery" and is_zip else "encrypted_pdfs.zip" if is_zip else f"protected_{Path(paths[0]).name}"
        output_path = output_dir / filename
        if mode == "recovery":
            recovery = parse_recovery_data()
            if not recovery:
                return error("Add at least one recovery question and answer.")
            encrypt_pdfs_with_recovery(paths, password, recovery, str(output_path))
        else:
            encrypt_pdfs_regular(paths, password, str(output_path))
        jobs = read_jobs()
        jobs[job_id]["outputs"] = [filename]
        write_jobs(jobs)
        shutil.rmtree(UPLOAD_DIR / job_id, ignore_errors=True)
        log_event("encrypted", user_id=user["id"], mode=mode, file_count=len(paths), filename=filename)
        return jsonify({"ok": True, "job_id": job_id, "filename": filename, "download_url": f"/downloads/{job_id}/{filename}"})
    except Exception as exc:
        log_event("encryption_failed", user_id=user["id"], mode=mode, error=str(exc))
        return error(str(exc), 400)


@app.get("/downloads/<job_id>/<path:filename>")
def download(job_id, filename):
    user, failure = require_user()
    if failure:
        return failure
    safe_job_id = secure_filename(job_id)
    safe_filename = secure_filename(filename)
    job = assert_job_owner(safe_job_id, user)
    if not job or safe_filename not in job.get("outputs", []):
        return error("Download expired or not found.", 404)
    directory = OUTPUT_DIR / safe_job_id
    return send_from_directory(directory, safe_filename, as_attachment=True)


@app.post("/api/recover")
@limiter.limit("10 per hour")
def recover():
    user, failure = require_user()
    if failure:
        return failure
    cleanup_old_jobs()
    try:
        uploaded = request.files.get("pdf")
        if not uploaded:
            return error("Upload a recovery-enabled PDF.")
        job_id, paths, _ = save_uploads([uploaded], user["id"])
        pdf_path = paths[0]
        answers_raw = request.form.get("answers")
        answers = json.loads(answers_raw) if answers_raw else None
        if answers is None:
            log_event("recovery_questions_read", user_id=user["id"])
            return jsonify({"ok": True, "questions": recovery_questions(pdf_path)})
        log_event("recovery_success", user_id=user["id"])
        return jsonify({"ok": True, "password": recover_password_from_pdf(pdf_path, answers)})
    except Exception as exc:
        log_event("recovery_failed", user_id=user["id"], error=str(exc))
        return error(str(exc), 400)


@app.get("/api/admin/summary")
def admin_summary():
    user, failure = require_admin_user()
    if failure:
        return failure
    users = read_users()
    events = read_events()
    support_items = read_support()
    encrypted = [event for event in events if event.get("type") == "encrypted"]
    regular = [event for event in encrypted if event.get("mode") == "regular"]
    recovery = [event for event in encrypted if event.get("mode") == "recovery"]
    return jsonify({
        "ok": True,
        "admin": public_user(user),
        "stats": {
            "users": len(users),
            "login_success": len([e for e in events if e.get("type") == "login_success"]),
            "login_failed": len([e for e in events if e.get("type") == "login_failed"]),
            "signups": len([e for e in events if e.get("type") == "signup"]),
            "regular_encryptions": len(regular),
            "recovery_encryptions": len(recovery),
            "recoveries": len([e for e in events if e.get("type") == "recovery_success"]),
            "queries": len(support_items),
        },
        "users": [public_user(account) for account in users],
        "logs": list(reversed(events[-20:])),
        "support": [public_support(item) for item in reversed(support_items[-20:])],
        "trend": [{"day": (int(time.time()) // 86400) - offset, "count": sum(1 for e in encrypted if int(e.get("created_at", 0)) // 86400 == (int(time.time()) // 86400) - offset)} for offset in range(6, -1, -1)],
    })


if __name__ == "__main__":
    ensure_dirs()
    app.run(host="0.0.0.0", port=8000, debug=ENV != "production")
