import json
import os
import secrets
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
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

# Database setup
# Use DATABASE_URL from env if available (e.g. Supabase Postgres), otherwise fallback to local SQLite
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/webauthn.db")
# Fix for Render/Supabase postgres:// instead of postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "webauthn_users"
    username = Column(String, primary_key=True, index=True)
    user_id_b64 = Column(String, nullable=False)
    credential_id_b64 = Column(String, nullable=False)
    public_key_b64 = Column(String, nullable=False)
    sign_count = Column(Integer, nullable=False)


Base.metadata.create_all(bind=engine)

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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_rp_id(request: Request) -> str:
    # In production, this should match your frontend domain (e.g. your-app.onrender.com)
    return request.url.hostname or "localhost"


def get_expected_origins(request: Request) -> list[str]:
    scheme = request.url.scheme
    host = request.url.hostname
    port = request.url.port
    if not host:
        return ["http://localhost:8000"]
    
    if port is None or (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return [f"{scheme}://{host}"]
    return [f"{scheme}://{host}:{port}"]


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/register/begin")
def register_begin(payload: UsernameBody, request: Request) -> dict[str, Any]:
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if user:
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

    db = SessionLocal()
    if db.query(User).filter(User.username == username).first():
        db.close()
        pending_registration.pop(username, None)
        raise HTTPException(status_code=409, detail="Username already registered")

    try:
        verification = verify_registration_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(state["challenge"]),
            expected_rp_id=get_rp_id(request),
            expected_origin=get_expected_origins(request),
        )
    except Exception as exc:
        db.close()
        pending_registration.pop(username, None)
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {exc}")

    new_user = User(
        username=username,
        user_id_b64=state["user_id"],
        credential_id_b64=bytes_to_base64url(verification.credential_id),
        public_key_b64=bytes_to_base64url(verification.credential_public_key),
        sign_count=verification.sign_count,
    )
    db.add(new_user)
    db.commit()
    db.close()
    
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

    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if not user:
        raise HTTPException(status_code=404, detail="Username is not registered")

    options = generate_authentication_options(
        rp_id=get_rp_id(request),
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(user.credential_id_b64),
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

    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user:
        db.close()
        pending_authentication.pop(username, None)
        raise HTTPException(status_code=404, detail="Username is not registered")

    try:
        verification = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=get_rp_id(request),
            expected_origin=get_expected_origins(request),
            credential_public_key=base64url_to_bytes(user.public_key_b64),
            credential_current_sign_count=int(user.sign_count),
        )
    except Exception as exc:
        db.close()
        pending_authentication.pop(username, None)
        raise HTTPException(status_code=400, detail=f"Login verification failed: {exc}")

    user.sign_count = verification.new_sign_count
    db.commit()
    db.close()
    
    pending_authentication.pop(username, None)
    return {"message": "Login successful"}


@app.post("/login/cancel")
def login_cancel(payload: UsernameBody) -> None:
    pending_authentication.pop(payload.username.strip(), None)
    raise HTTPException(status_code=400, detail="Login validation cancelled by user")
