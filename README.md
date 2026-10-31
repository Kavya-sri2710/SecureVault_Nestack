# SecureVault — Nestack Secure Records API

A security-focused multi-tenant records API with a human-centered frontend preview. Python, FastAPI, SQLite, and custom session/access-control logic. No authentication framework is used.

## Included assessment requirements

1. **Registration/login:** salted, deliberately expensive scrypt password derivation; no plaintext passwords; secure random opaque bearer token after successful login.
2. **Records and ownership:** authenticated create/read routes; ordinary users' reads include both record ID and owner ID in the SQL predicate. A foreign or missing record returns 404.
3. **Admin:** admins can read any record. Registration rejects extra fields such as `role`. There is no user-facing role-edit route. A trusted operator can provision an existing account as admin using `python provision_admin.py <username>`.
4. **Security protections:** Pydantic type/length/presence validation (invalid payloads return 400), parameterized SQL, per-account failed-login lockout (429), session token digest lookup and expiry on every protected request, and record-level authorization.
5. **Documentation/tests:** this README documents threat assumptions and security decisions; automated tests exercise ownership denial, admin access, role field rejection, lockout, validation, session authentication, list isolation, and the OpenAPI bearer scheme.

## Run locally

Python 3.11+ is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

API docs: http://127.0.0.1:8000/docs

**Swagger authentication:** click **Authorize** near the top of `/docs`, enter the access token returned by `/login` (use the `Bearer` scheme; Swagger adds the prefix), then authorize. Protected routes should show the lock icon.

Health: http://127.0.0.1:8000/health

The SQLite database is `records.db` by default. Set `DATABASE_PATH` to use another location. `MAX_LOGIN_FAILURES`, `LOGIN_LOCK_SECONDS`, and `SESSION_SECONDS` can be configured using environment variables.

## Routes

- `POST /register` — `{ "username": "...", "password": "at-least-12-chars" }` → 201; role always `user`.
- `POST /login` — same credentials → 200 with bearer token; 401 invalid credentials; 429 lockout.
- `POST /records` — bearer token and `{ "title": "...", "body": "..." }` → 201.
- `GET /records` — bearer token; returns only the caller’s records (admins can list all).
- `GET /records/{id}` — bearer token; 200 if owner or admin, otherwise 404.
- `GET /health` — health response.

## Security decisions and threat model

### Passwords and user-table leakage
Passwords are hashed with Python `hashlib.scrypt` using N=2^14, r=8, p=1, a 64-byte derived value, and an independently generated 16-byte salt per user. Only the salt and derived hash are persisted. A leaked users table does not reveal plaintext passwords; however, an attacker could still perform offline password guesses, so strong unique passwords and suitable hashing cost remain important.

### Sessions
Login creates a cryptographically random opaque bearer token using `secrets.token_urlsafe`. The database stores only its SHA-256 digest, user association, and expiry (eight hours by default). Each protected request hashes the presented token and checks the stored session and expiry. A database leak alone does not disclose active bearer tokens.

### Record-level access control / IDOR
The normal-user SQL query is `WHERE id=? AND user_id=?`, so authentication alone never grants access to a record. A record belonging to another account and a nonexistent record both return 404, reducing record-ID enumeration. Admins are allowed to read across owners.

### Admin assignment / privilege escalation
The API does not accept role input on registration and has no self-service role modification route. Admin role assignment is an operator-only command that updates an existing account using a parameterized query. Protect the host and database access; the provisioning utility is not an HTTP endpoint.

### Brute force
Failed login attempts are tracked per account rather than per IP. After the configured threshold (five by default), the account is locked for the configured duration (15 minutes by default) and returns 429. A successful login resets the counter. A production multi-instance service should use atomic shared storage and design recovery controls to mitigate lockout-based denial of service.

### Input and database handling
Request models enforce field presence, type, character/length bounds, and reject unexpected fields. Validation failures are mapped to 400. All SQL values use bound parameters; user input is never concatenated into SQL statements. Request body limits should additionally be enforced at a production reverse proxy.

### Production considerations
Use HTTPS, restrictive DB permissions, monitored backups, environment-based configuration, dependency updates, and a production ASGI server. Never commit database files, credentials, or environment secrets. The assessment repository must be private and `roy-nestack` added as collaborator.

## Tests

```bash
pytest -q
```

The tests cover user registration and ownership isolation, admin cross-owner read, role injection rejection, account lockout, unauthenticated access, validation, invalid session rejection, user-scoped record listing, and Swagger/OpenAPI bearer authorization metadata.

## Frontend preview

Open `frontend/index.html` in a browser to view the responsive SecureVault UI. The current HTML/CSS/JavaScript UI is a frontend preview using client-side demo state; it is **not yet wired to the API**. The API is the source of truth for the assessment. Do not claim the preview is integrated until frontend API calls are implemented.
