"""Controlled local admin provisioning utility; not an HTTP endpoint.
Usage: python provision_admin.py username
Run only by a trusted operator with access to the application database.
"""
import sys
from app import db

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python provision_admin.py <existing-username>")
    username = sys.argv[1]
    with db() as c:
        cur = c.execute("UPDATE users SET role='admin' WHERE username=?", (username,))
        if cur.rowcount != 1:
            raise SystemExit(f"No account found for username: {username}")
    print(f"Granted admin role to {username!r}. Provisioning is server-side only.")

if __name__ == "__main__":
    main()
