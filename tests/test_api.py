import os, tempfile
_tmp = tempfile.NamedTemporaryFile(delete=False)
_tmp.close()
os.environ["DATABASE_PATH"] = _tmp.name
os.environ["MAX_LOGIN_FAILURES"] = "3"
os.environ["LOGIN_LOCK_SECONDS"] = "60"

from fastapi.testclient import TestClient
from app import app, db
client = TestClient(app)

def signup(name, password="strong-password-123"):
    return client.post("/register", json={"username": name, "password": password})

def login(name, password="strong-password-123"):
    return client.post("/login", json={"username": name, "password": password})

def bearer(name):
    token = login(name).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_user_can_create_and_read_own_record_and_other_user_cannot():
    assert signup("alice").status_code == 201
    assert signup("bob").status_code == 201
    alice, bob = bearer("alice"), bearer("bob")
    created = client.post("/records", headers=alice, json={"title":"Private","body":"Alice's data"})
    assert created.status_code == 201
    rid = created.json()["id"]
    assert client.get(f"/records/{rid}", headers=alice).status_code == 200
    assert client.get(f"/records/{rid}", headers=bob).status_code == 404

def test_role_field_is_rejected_at_registration():
    response = client.post("/register", json={"username":"eve",
        "password":"strong-password-123", "role":"admin"})
    assert response.status_code == 400

def test_admin_can_read_other_users_record():
    signup("reader")
    signup("owner")
    owner_headers = bearer("owner")
    record = client.post("/records", headers=owner_headers,
                         json={"title":"Owner record","body":"Sensitive"})
    with db() as c:
        c.execute("UPDATE users SET role='admin' WHERE username='reader'")
    admin_headers = bearer("reader")
    assert client.get(f"/records/{record.json()['id']}", headers=admin_headers).status_code == 200

def test_login_lockout_returns_429_after_threshold():
    signup("lockme")
    assert login("lockme","incorrect-password").status_code == 401
    assert login("lockme","incorrect-password").status_code == 401
    assert login("lockme","incorrect-password").status_code == 429
    assert login("lockme").status_code == 429

def test_auth_required_and_validation_returns_400():
    assert client.post("/records", json={"title":"x","body":"y"}).status_code == 401
    signup("validuser")
    headers=bearer("validuser")
    assert client.post("/records", headers=headers, json={"title":"","body":"ok"}).status_code == 400

def test_expired_or_invalid_session_is_401():
    response=client.get("/records/1",headers={"Authorization":"Bearer not-a-real-token"})
    assert response.status_code == 401

def test_list_records_is_scoped_to_authenticated_owner():
    signup("list_alice")
    signup("list_bob")
    alice_headers = bearer("list_alice")
    bob_headers = bearer("list_bob")
    alice_record = client.post("/records", headers=alice_headers,
                               json={"title": "Alice only", "body": "Private"})
    bob_record = client.post("/records", headers=bob_headers,
                             json={"title": "Bob only", "body": "Private"})
    assert alice_record.status_code == 201
    assert bob_record.status_code == 201
    alice_list = client.get("/records", headers=alice_headers)
    assert alice_list.status_code == 200
    assert [item["title"] for item in alice_list.json()] == ["Alice only"]
    assert client.get("/records", headers=bob_headers).json()[0]["title"] == "Bob only"

def test_openapi_exposes_bearer_authorize_scheme():
    schema = client.get("/openapi.json").json()
    schemes = schema["components"]["securitySchemes"]
    assert "BearerAuth" in schemes
    assert schemes["BearerAuth"]["scheme"] == "bearer"
    assert schema["paths"]["/records"]["post"]["security"] == [{"BearerAuth": []}]
