import os
import hashlib
import hmac
import secrets
import sqlite3
import time
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict

DB_PATH = os.getenv("DATABASE_PATH", "records.db")
MAX_FAILURES = int(os.getenv("MAX_LOGIN_FAILURES", "5"))
LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))
SESSION_SECONDS = int(os.getenv("SESSION_SECONDS", str(8 * 60 * 60)))
app = FastAPI(title="SecureVault — Nestack Secure Records API", version="1.2.0")
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="BearerAuth")

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          salt TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
          failed_attempts INTEGER NOT NULL DEFAULT 0,
          locked_until INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS records (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL,
          body TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        """)
init_db()

@app.exception_handler(RequestValidationError)
async def validation_error_as_400(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"detail": "Invalid request data"})

class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)

class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)

class RecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    body: str = Field(min_length=1, max_length=10000)

def hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64).hex()

def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
    # HTTPBearer provides a real OpenAPI security scheme and Swagger's Authorize control.
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required")
    token = credentials.credentials.strip()
    if not token or len(token) > 256:
        raise HTTPException(status_code=401, detail="Invalid session")
    now = int(time.time())
    with db() as c:
        row = c.execute("""SELECT u.id,u.username,u.role,s.expires_at
                           FROM sessions s JOIN users u ON u.id=s.user_id
                           WHERE s.token_hash=?""", (token_digest(token),)).fetchone()
        if not row or row["expires_at"] <= now:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(token),))
            invalid = True
        else:
            invalid = False
            result = dict(row)
    if invalid:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return result

@app.post("/register", status_code=201)
def register(payload: RegisterIn):
    salt = secrets.token_bytes(16)
    pwh = hash_password(payload.password, salt)
    try:
        with db() as c:
            c.execute("INSERT INTO users(username,password_hash,salt,role) VALUES(?,?,?,'user')",
                      (payload.username, pwh, salt.hex()))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    return {"message": "Account created", "username": payload.username, "role": "user"}

@app.post("/login")
def login(payload: LoginIn):
    now = int(time.time())
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()
        if not user:
            # Perform a dummy costly derivation to reduce account-enumeration timing differences.
            hash_password(payload.password, b"0123456789abcdef")
            bad_user = True
            locked = False
            invalid = False
        elif user["locked_until"] > now:
            bad_user = False
            locked = True
            invalid = False
        else:
            bad_user = False
            locked = False
            computed = hash_password(payload.password, bytes.fromhex(user["salt"]))
            invalid = not hmac.compare_digest(computed, user["password_hash"])
            if invalid:
                failures = user["failed_attempts"] + 1
                lock_until = now + LOCK_SECONDS if failures >= MAX_FAILURES else 0
                c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                          (failures, lock_until, user["id"]))
            else:
                c.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (user["id"],))
                token = secrets.token_urlsafe(32)
                c.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                          (token_digest(token), user["id"], now + SESSION_SECONDS))
    if bad_user or invalid:
        if user and user["failed_attempts"] + 1 >= MAX_FAILURES:
            raise HTTPException(status_code=429, detail="Account temporarily locked")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if locked:
        raise HTTPException(status_code=429, detail="Account temporarily locked")
    return {"access_token": token, "token_type": "bearer", "expires_in": SESSION_SECONDS}

@app.post("/records", status_code=201)
def create_record(payload: RecordIn, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("INSERT INTO records(user_id,title,body,created_at) VALUES(?,?,?,?)",
                        (user["id"], payload.title, payload.body, int(time.time())))
        rid = cur.lastrowid
    return {"id": rid, "title": payload.title}

@app.get("/records")
def list_records(user=Depends(current_user)):
    """List records owned by the authenticated user; admins can view all records."""
    with db() as c:
        if user["role"] == "admin":
            rows = c.execute(
                "SELECT id,user_id,title,body,created_at FROM records ORDER BY created_at DESC,id DESC"
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT id,user_id,title,body,created_at FROM records WHERE user_id=? ORDER BY created_at DESC,id DESC",
                (user["id"],),
            ).fetchall()
    return [dict(row) for row in rows]


@app.get("/records/{record_id}")
def get_record(record_id: int, user=Depends(current_user)):
    if record_id <= 0:
        raise HTTPException(status_code=400, detail="Record id must be positive")
    with db() as c:
        if user["role"] == "admin":
            row = c.execute("SELECT id,user_id,title,body,created_at FROM records WHERE id=?",
                            (record_id,)).fetchone()
        else:
            row = c.execute("""SELECT id,user_id,title,body,created_at FROM records
                               WHERE id=? AND user_id=?""", (record_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Record not found")
    return dict(row)

@app.get("/health")
def health():
    return {"status": "ok"}
