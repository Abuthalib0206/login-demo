from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
import mysql.connector
from mysql.connector import Error
from cryptography.fernet import Fernet
import dbconfig

app = FastAPI()

# Templates
templates = Jinja2Templates(directory="templates")

# DB Credentials
db_cred = dbconfig.db_config()


key = Fernet.generate_key()
with open("secret.key", "wb") as key_file:
    
    key_file.write(key)

print("secret.key created successfully!")

# -----------------------------
# Load AES Key
# -----------------------------
def load_key():
    return open("secret.key", "rb").read()

aes_key = load_key()
cipher = Fernet(aes_key)



def encrypt_password(password: str):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(enc_pass: str):
    return cipher.decrypt(enc_pass.encode()).decode()


# -----------------------------
# MySQL Connection
# -----------------------------
def get_connection():
    try:
        return mysql.connector.connect(**db_cred)
    except Error as e:
        print("MySQL Connection Error:", e)
        return None


# -----------------------------
# Render Pages
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# -----------------------------
# Register User
# -----------------------------
@app.post("/register_user")
def register_user(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    conn = get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="DB connection failed")

    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    existing = cursor.fetchone()

    if existing:
        return RedirectResponse("/register?error=Email already registered", status_code=303)

    encrypted_pass = encrypt_password(password)

    cursor.execute(
        "INSERT INTO users (name, email, pass, status) VALUES (%s, %s, %s, %s)",
        (name, email, encrypted_pass, 1)
    )
    conn.commit()

    return RedirectResponse("/?msg=Registered successfully", status_code=303)


# -----------------------------
# Login User
# -----------------------------
@app.post("/login_user")
def login_user(
    email: str = Form(...),
    password: str = Form(...)
):
    conn = get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="DB connection failed")

    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user:
        return RedirectResponse("/login?error=User not found", status_code=303)

    try:
        decrypted = decrypt_password(user["pass"])
    except:
        return RedirectResponse("/login?error=Error decrypting password", status_code=303)

    if decrypted != password:
        return RedirectResponse("/login?error=Invalid password", status_code=303)

    return RedirectResponse(f"/dashboard?name={user['name']}", status_code=303)


# -----------------------------
# Dashboard
# -----------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, name: str = ""):
    return templates.TemplateResponse("dashboard.html", {"request": request, "name": name})
