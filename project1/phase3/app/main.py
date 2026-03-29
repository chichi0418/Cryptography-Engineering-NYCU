import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json,
)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "webauthn.db"

app = FastAPI(title="Phase 3 - Simplified Hardware Login")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

pending_registration: dict[str, dict[str, Any]] = {}
pending_authentication: dict[str, str] = {}


class UsernameBody(BaseModel):
    username: str


class FinishBody(BaseModel):
    username: str
    credential: Optional[dict[str, Any]]


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                user_id_b64 TEXT NOT NULL,
                credential_id_b64 TEXT NOT NULL,
                public_key_b64 TEXT NOT NULL,
                sign_count INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def startup() -> None:
    init_db()


def get_rp_id(request: Request) -> str:
    host = request.url.hostname
    if host is None:
        raise HTTPException(status_code=400, detail="Unable to resolve RP ID")
    return host


def get_expected_origins(request: Request) -> list[str]:
    host = request.url.hostname
    scheme = request.url.scheme
    port = request.url.port
    if host is None:
        raise HTTPException(status_code=400, detail="Unable to resolve request origin")

    if port is None:
        return [f"{scheme}://{host}"]
    return [f"{scheme}://{host}:{port}"]


def db_fetch_user(username: str) -> Optional[sqlite3.Row]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()


def db_insert_user(
    username: str,
    user_id_b64: str,
    credential_id_b64: str,
    public_key_b64: str,
    sign_count: int,
) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO users (username, user_id_b64, credential_id_b64, public_key_b64, sign_count)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, user_id_b64, credential_id_b64, public_key_b64, sign_count),
        )
        conn.commit()
    finally:
        conn.close()


def db_update_sign_count(username: str, new_sign_count: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE users SET sign_count = ? WHERE username = ?",
            (new_sign_count, username),
        )
        conn.commit()
    finally:
        conn.close()


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/register/begin")
def register_begin(payload: UsernameBody, request: Request) -> dict[str, Any]:
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    if db_fetch_user(username):
        raise HTTPException(status_code=409, detail="Username already registered")

    rp_id = get_rp_id(request)
    user_id = secrets.token_bytes(16)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="Project1 Phase3",
        user_id=user_id,
        user_name=username,
        user_display_name=username,
    )

    pending_registration[username] = {
        "challenge": bytes_to_base64url(options.challenge),
        "user_id": bytes_to_base64url(user_id),
    }

    return {
        "publicKey": json.loads(options_to_json(options)),
        "message": "Registration challenge generated",
    }


@app.post("/register/finish")
def register_finish(payload: FinishBody, request: Request) -> dict[str, str]:
    username = payload.username.strip()
    state = pending_registration.get(username)
    if not state:
        raise HTTPException(status_code=400, detail="No pending registration for this username")

    if payload.credential is None:
        pending_registration.pop(username, None)
        raise HTTPException(status_code=400, detail="Registration cancelled by user")

    if db_fetch_user(username):
        pending_registration.pop(username, None)
        raise HTTPException(status_code=409, detail="Username already registered")

    try:
        verification = verify_registration_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(state["challenge"]),
            expected_rp_id=get_rp_id(request),
            expected_origin=get_expected_origins(request),
        )
    except Exception as exc:  # pragma: no cover - message path is the key behavior
        pending_registration.pop(username, None)
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {exc}")

    db_insert_user(
        username=username,
        user_id_b64=state["user_id"],
        credential_id_b64=bytes_to_base64url(verification.credential_id),
        public_key_b64=bytes_to_base64url(verification.credential_public_key),
        sign_count=verification.sign_count,
    )
    pending_registration.pop(username, None)

    return {"message": "Registration successful"}


@app.post("/register/cancel")
def register_cancel(payload: UsernameBody) -> None:
    pending_registration.pop(payload.username.strip(), None)
    raise HTTPException(status_code=400, detail="Registration cancelled by user")


@app.post("/login/begin")
def login_begin(payload: UsernameBody, request: Request) -> dict[str, Any]:
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    user = db_fetch_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="Username is not registered")

    options = generate_authentication_options(
        rp_id=get_rp_id(request),
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(user["credential_id_b64"]),
            )
        ],
    )

    pending_authentication[username] = bytes_to_base64url(options.challenge)

    return {
        "publicKey": json.loads(options_to_json(options)),
        "message": "Login challenge generated",
    }


@app.post("/login/finish")
def login_finish(payload: FinishBody, request: Request) -> dict[str, str]:
    username = payload.username.strip()
    challenge_b64 = pending_authentication.get(username)
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="No pending login for this username")

    if payload.credential is None:
        pending_authentication.pop(username, None)
        raise HTTPException(status_code=400, detail="Login validation cancelled by user")

    user = db_fetch_user(username)
    if not user:
        pending_authentication.pop(username, None)
        raise HTTPException(status_code=404, detail="Username is not registered")

    try:
        verification = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=get_rp_id(request),
            expected_origin=get_expected_origins(request),
            credential_public_key=base64url_to_bytes(user["public_key_b64"]),
            credential_current_sign_count=int(user["sign_count"]),
        )
    except Exception as exc:  # pragma: no cover - message path is the key behavior
        pending_authentication.pop(username, None)
        raise HTTPException(status_code=400, detail=f"Login verification failed: {exc}")

    db_update_sign_count(username=username, new_sign_count=verification.new_sign_count)
    pending_authentication.pop(username, None)

    return {"message": "Login successful"}


@app.post("/login/cancel")
def login_cancel(payload: UsernameBody) -> None:
    pending_authentication.pop(payload.username.strip(), None)
    raise HTTPException(status_code=400, detail="Login validation cancelled by user")
