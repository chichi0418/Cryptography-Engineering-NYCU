"""
Database layer using SQLAlchemy (already in requirements.txt).
Password hashing uses PBKDF2-HMAC-SHA256 from Python stdlib — no extra deps.
TOTP secret is a 160-bit random value encoded as base32 (Google Authenticator compatible).
"""

import base64
import hashlib
import os
import secrets

from sqlalchemy import Boolean, Column, Integer, String, create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Session

# Database file lives in /workspace (the Docker working dir)
DATABASE_URL = "sqlite:////workspace/phase2.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    username      = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)   # "salt$hash" (hex)
    totp_secret   = Column(String, nullable=False)   # base32 string


def init_db() -> None:
    """Create all tables. Safe to call multiple times."""
    Base.metadata.create_all(engine)


# ── Password helpers (PBKDF2, stdlib only) ────────────────────────────────────

def _hash_password(password: str) -> str:
    """Return 'hex_salt$hex_hash' string."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex() + "$" + dk.hex()


def _check_password(password: str, stored: str) -> bool:
    """Verify password against stored 'salt$hash' string."""
    salt_hex, hash_hex = stored.split("$", 1)
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(dk.hex(), hash_hex)


# ── Public API ────────────────────────────────────────────────────────────────

def create_user(username: str, password: str) -> str:
    """
    Register a new user.

    Generates a cryptographically random 160-bit TOTP secret (base32),
    hashes the password with PBKDF2-SHA256, and stores both.

    Returns:
        The base32 TOTP secret (caller should show it to the user once).

    Raises:
        ValueError: if the username is already taken.
    """
    pw_hash = _hash_password(password)
    # 20 random bytes → base32 string (160-bit, Google Authenticator compatible)
    totp_secret = base64.b32encode(secrets.token_bytes(20)).decode()

    with Session(engine) as session:
        user = User(username=username, password_hash=pw_hash, totp_secret=totp_secret)
        session.add(user)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise ValueError(f"Username '{username}' is already taken.")

    return totp_secret


def get_user(username: str) -> User | None:
    """Return the User ORM object, or None if not found."""
    with Session(engine) as session:
        user = session.query(User).filter_by(username=username).first()
        if user:
            # Detach from session so caller can use it after session closes
            session.expunge(user)
        return user


def authenticate_password(username: str, password: str) -> User | None:
    """
    Check username + password.

    Returns the User if credentials are valid, None otherwise.
    Always runs the password check even when the user doesn't exist
    (constant-time: prevents username enumeration via timing).
    """
    user = get_user(username)
    dummy_hash = "0" * 32 + "$" + "0" * 64   # used when user not found
    stored = user.password_hash if user else dummy_hash
    valid = _check_password(password, stored)
    return user if (user and valid) else None
