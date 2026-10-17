from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("DATA_DIR", str(ROOT / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "admin-audit.sqlite3"
COOKIE_NAME = "modelscope_admin"
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "12"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError("Set ADMIN_USERNAME and ADMIN_PASSWORD before starting the service.")

app = FastAPI(title="ModelScope Admin Audit API", docs_url=None, redoc_url=None)
app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS admin_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                ip_address TEXT NOT NULL,
                login_at TEXT NOT NULL,
                logout_at TEXT
            )"""
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_sessions_login_at ON admin_sessions(login_at DESC)")


init_db()


def client_ip(request: Request) -> str:
    # Only trust X-Forwarded-For when deployment is behind a trusted reverse proxy.
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_session(request: Request) -> sqlite3.Row:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录管理员账号")
    cutoff = (utc_now() - timedelta(hours=SESSION_HOURS)).isoformat()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM admin_sessions WHERE token_hash=? AND logout_at IS NULL AND login_at>=?",
            (token_hash(token), cutoff),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录已过期，请重新登录")
    return row


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "index.html", media_type="text/html; charset=utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, str]:
    valid_user = hmac.compare_digest(body.username.encode(), ADMIN_USERNAME.encode())
    valid_password = hmac.compare_digest(body.password.encode(), ADMIN_PASSWORD.encode())
    if not (valid_user and valid_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="账号或密码不正确")

    token = secrets.token_urlsafe(32)
    now = utc_now()
    with db() as conn:
        conn.execute(
            "INSERT INTO admin_sessions(username, token_hash, ip_address, login_at) VALUES(?,?,?,?)",
            (ADMIN_USERNAME, token_hash(token), client_ip(request), now.isoformat()),
        )
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_HOURS * 60 * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"ok": "true"}


@app.post("/api/logout")
def logout(request: Request, response: Response) -> dict[str, str]:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        with db() as conn:
            conn.execute(
                "UPDATE admin_sessions SET logout_at=? WHERE token_hash=? AND logout_at IS NULL",
                (utc_now().isoformat(), token_hash(token)),
            )
    response.delete_cookie(COOKIE_NAME, path="/", secure=COOKIE_SECURE, httponly=True, samesite="lax")
    return {"ok": "true"}


@app.get("/api/me")
def me(session: sqlite3.Row = Depends(current_session)) -> dict[str, str]:
    return {"username": session["username"]}


@app.get("/api/admin/sessions")
def sessions(_: sqlite3.Row = Depends(current_session)) -> dict[str, list[dict[str, str | None]]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT ip_address, login_at, logout_at FROM admin_sessions ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return {"sessions": [dict(row) for row in rows]}

