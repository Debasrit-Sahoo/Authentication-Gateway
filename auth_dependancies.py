from fastapi import Header, HTTPException
from db import get_username
from datetime import datetime, timedelta, timezone

TOKEN_EXPIRY_MINUTES = 30

def get_cur_session(authorization: str | None = Header(default=None)) -> tuple[str, str]:
    if not authorization:
        raise HTTPException(401, "Missing Authorization header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Invalid Authorization header")
    
    token = authorization.removeprefix("Bearer ").strip()

    username, created_at = get_username(token)
    if not username or not created_at:
        raise HTTPException(401, "Invalid or expired token")
    try:
        created_dt = datetime.fromisoformat(created_at)
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
    except Exception:
        raise HTTPException(401, "Invalid token timestamp")
    
    if datetime.now(timezone.utc) - created_dt > timedelta(minutes=TOKEN_EXPIRY_MINUTES):
        raise HTTPException(401, "Token expired")
    
    return username, token