import sqlite3
from datetime import datetime, timezone

DB_NAME = "users.db"

def get_db():
    return sqlite3.connect(DB_NAME)

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL)
                """)
    cur.execute("""
CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY, username TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
""")
    db.commit()
    db.close()

def is_registered(username: str) -> bool:
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT 1 FROM users WHERE username=?", (username,)
    )
    exists = True if cur.fetchone() else False
    db.close()
    return exists

def put_user(username: str, password_hash: bytes):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash)
    )
    db.commit()
    db.close()

def fetch_hash(username: str) -> bytes | None:
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    hash = cur.fetchone()
    db.close()
    if not hash: return None
    return hash[0]

def store_token(username: str, token: str):
    db = get_db()
    cur = db.cursor()

    cur.execute(
        "DELETE FROM tokens WHERE username = ?", (username,)
    )

    cur.execute(
        "INSERT INTO tokens (token, username, created_at) VALUES (?, ?, ?)", (token, username, datetime.now(timezone.utc).isoformat())
    )

    db.commit()
    db.close()

def get_username(token: str) -> tuple[str | None, str | None]:
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username, created_at FROM tokens WHERE token = ?", (token,))
    r = cur.fetchone()
    db.close()

    if not r: return None, None
    return r[0], r[1]