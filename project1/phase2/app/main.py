"""
Phase 2 — Symmetric 2FA with TOTP (HMAC-SHA1).

Run command (from spec):
    docker compose exec app uvicorn phase2.app.main:app \
        --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .db import authenticate_password, create_user, init_db
from .totp import verify_totp

app = FastAPI(title="Phase 2 — TOTP 2FA")

# Path is relative to the working dir /workspace (set in docker-compose.yml)
templates = Jinja2Templates(directory="phase2/app/templates")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ── Root ──────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# ── Register ──────────────────────────────────────────────────────────────────

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    try:
        secret = create_user(username, password)
    except ValueError as e:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": str(e)},
        )

    # Show the secret exactly once — user must save it into their authenticator
    return templates.TemplateResponse(
        "secret.html",
        {"request": request, "secret": secret, "username": username},
    )


# ── Login ─────────────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(...),
):
    # Step 1 — verify password
    user = authenticate_password(username, password)
    if user is None:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password."},
        )

    # Step 2 — verify TOTP code (window=1 → checks T-1, T, T+1)
    if not verify_totp(user.totp_secret, totp_code):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid or expired authenticator code. Please try again."},
        )

    return templates.TemplateResponse(
        "success.html",
        {"request": request, "username": username},
    )
