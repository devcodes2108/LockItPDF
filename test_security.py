import importlib
import io
import json
import sys
import time

from werkzeug.security import generate_password_hash


def load_app(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("LOCKITPDF_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-with-enough-entropy")
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setenv("LOCKITPDF_ADMIN_EMAIL", "admin@example.com")
    for key, value in env.items():
        monkeypatch.setenv(key, str(value))
    sys.modules.pop("app", None)
    return importlib.import_module("app")


def signup(client, username="alice", email="alice@example.com", password="Strong1!"):
    return client.post("/api/signup", json={"username": username, "email": email, "password": password})


def login(client, username="alice@example.com", password="Strong1!"):
    return client.post("/api/login", json={"username": username, "password": password})


def pdf_file(name="doc.pdf"):
    return io.BytesIO(b"%PDF-1.4\n%test\n")


def test_signup_hashes_with_argon2_and_sets_secure_cookie(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    client = app_module.app.test_client()

    response = signup(client)

    assert response.status_code == 201
    users = app_module.read_users()
    assert users[0]["password_hash"].startswith("$argon2")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


def test_legacy_password_hash_is_rehashed_after_login(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    legacy = generate_password_hash("Strong1!")
    app_module.write_users([
        {
            "id": "user-1",
            "username": "legacy",
            "email": "legacy@example.com",
            "password_hash": legacy,
            "role": "user",
            "email_verified": True,
        }
    ])

    response = login(app_module.app.test_client(), "legacy@example.com")

    assert response.status_code == 200
    assert app_module.read_users()[0]["password_hash"].startswith("$argon2")


def test_password_reset_token_expires_and_is_single_use(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    app_module.write_users([
        {
            "id": "user-1",
            "username": "alice",
            "email": "alice@example.com",
            "password_hash": app_module.hash_password("Strong1!"),
            "role": "user",
            "email_verified": True,
        }
    ])
    raw = app_module.token_record("user-1", "password_reset")
    tokens = app_module.read_tokens()
    tokens[0]["expires_at"] = int(time.time()) - 1
    app_module.write_tokens(tokens)

    expired = app_module.app.test_client().post("/api/password-reset/confirm", json={"token": raw, "password": "NewStrong1!"})

    assert expired.status_code == 400
    fresh = app_module.token_record("user-1", "password_reset")
    first = app_module.app.test_client().post("/api/password-reset/confirm", json={"token": fresh, "password": "NewStrong1!"})
    second = app_module.app.test_client().post("/api/password-reset/confirm", json={"token": fresh, "password": "NewStrong1!"})
    assert first.status_code == 200
    assert second.status_code == 400


def test_failed_login_lockout_sets_retry_after(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path, LOCKITPDF_FAILED_LOGIN_LIMIT=2)
    client = app_module.app.test_client()
    signup(client)

    first = client.post("/api/login", json={"username": "alice@example.com", "password": "Wrong1!"})
    second = client.post("/api/login", json={"username": "alice@example.com", "password": "Wrong1!"})
    locked = client.post("/api/login", json={"username": "alice@example.com", "password": "Strong1!"})

    assert first.status_code == 401
    assert second.status_code == 401
    assert "Retry-After" in second.headers
    assert locked.status_code == 423


def test_rate_limit_returns_json(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    client = app_module.app.test_client()

    response = None
    for _ in range(11):
        response = client.post("/api/login", json={"username": "missing@example.com", "password": "Wrong1!"})

    assert response.status_code == 429
    assert response.get_json()["ok"] is False


def test_download_requires_job_ownership(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    owner_id = "owner"
    other_id = "other"
    job_id = "job123"
    app_module.write_users([
        {"id": owner_id, "username": "owner", "email": "owner@example.com", "password_hash": app_module.hash_password("Strong1!"), "role": "user", "email_verified": True},
        {"id": other_id, "username": "other", "email": "other@example.com", "password_hash": app_module.hash_password("Strong1!"), "role": "user", "email_verified": True},
    ])
    output_dir = app_module.OUTPUT_DIR / job_id
    output_dir.mkdir(parents=True)
    (output_dir / "protected.pdf").write_bytes(b"%PDF-1.4\n")
    app_module.write_jobs({job_id: {"owner_id": owner_id, "created_at": int(time.time()), "outputs": ["protected.pdf"]}})
    client = app_module.app.test_client()
    login(client, "other@example.com")

    response = client.get(f"/downloads/{job_id}/protected.pdf")

    assert response.status_code == 404


def test_upload_rejects_non_pdf_and_accepts_owned_pdf(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    monkeypatch.setattr(app_module, "encrypt_pdfs_regular", lambda paths, password, output: open(output, "wb").write(b"%PDF-1.4\n"))
    client = app_module.app.test_client()
    signup(client)

    bad = client.post(
        "/api/upload",
        data={"password": "Strong1!", "mode": "regular", "pdfs[]": (io.BytesIO(b"not-pdf"), "x.pdf")},
        content_type="multipart/form-data",
    )
    good = client.post(
        "/api/upload",
        data={"password": "Strong1!", "mode": "regular", "pdfs[]": (pdf_file(), "../safe.pdf")},
        content_type="multipart/form-data",
    )

    assert bad.status_code == 400
    assert good.status_code == 200
    job_id = good.get_json()["job_id"]
    assert app_module.read_jobs()[job_id]["owner_id"] == app_module.read_users()[0]["id"]


def test_recover_requires_authentication(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)

    response = app_module.app.test_client().post(
        "/api/recover",
        data={"pdf": (pdf_file(), "locked.pdf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 401


def test_admin_endpoint_rejects_non_admin_and_allows_admin(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    non_admin = app_module.app.test_client()
    admin = app_module.app.test_client()
    signup(non_admin)
    signup(admin, "admin", "admin@example.com")

    denied = non_admin.get("/api/admin/summary")
    allowed = admin.get("/api/admin/summary")

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.get_json()["admin"]["role"] == "admin"


def test_admin_page_requires_admin_secret(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path, ADMIN_SECRET="supersecret")
    client = app_module.app.test_client()

    missing = client.get("/admin.html")
    invalid = client.get("/admin.html", headers={"X-Admin-Secret": "wrong"})
    valid = client.get("/admin.html", headers={"X-Admin-Secret": "supersecret"})

    assert missing.status_code == 403
    assert invalid.status_code == 403
    assert valid.status_code == 200
    assert b"Admin | LockItPDF" in valid.data


def test_support_query_is_saved_and_visible_to_admin(monkeypatch, tmp_path):
    app_module = load_app(monkeypatch, tmp_path)
    sent = []
    monkeypatch.setattr(app_module, "send_email", lambda to, subject, body: sent.append((to, subject, body)) or True)
    admin = app_module.app.test_client()
    signup(admin, "admin", "admin@example.com")

    response = app_module.app.test_client().post(
        "/api/support",
        json={"name": "Visitor", "email": "visitor@example.com", "message": "Please help with uploads."},
    )
    summary = admin.get("/api/admin/summary")

    assert response.status_code == 201
    assert summary.status_code == 200
    assert summary.get_json()["stats"]["queries"] == 1
    assert summary.get_json()["support"][0]["message"] == "Please help with uploads."
    assert sent and sent[0][0] == "admin@example.com"
