from fastapi import FastAPI, HTTPException, Depends, Request
import time
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from db import init_db, put_user, is_registered, fetch_hash, store_token, delete_token, delete_user
from auth import hash_password, compare_password, generate_token
from schemas import LoginRequest
from auth_dependancies import get_cur_session
import os
import httpx

INTERNAL_API_URL = os.environ["INTERNAL_API_URL"]
GATEWAY_SECRET = os.environ["GATEWAY_SECRET"]

if not INTERNAL_API_URL or not GATEWAY_SECRET:
    raise RuntimeError("Missing INTERNAL_API_URL or GATEWAY_SECRET")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("Server booting...")
    print("Tables initialized")

    yield

    print("Server shutting down...")

app = FastAPI(lifespan=lifespan)

window = 30*60
max_requests = 50

rate_limit_store: dict[str, list[float]] = {}

PROTECTED_PATHS = {"/login", "/register", "/secret/nuclear_codes", "/me", "/logout", "/deregister"}

@app.middleware("http")
async def rate_limiter(request: Request, call_next):
    if request.url.path not in PROTECTED_PATHS:
        return await call_next(request)

    ip = request.headers.get("X-Forwarded-For")
    if ip:
        ip = ip.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else "unknown"

    now = time.time()

    timestamps = rate_limit_store.get(ip, [])
    timestamps = [t for t in timestamps if now - t < window]
    if len(timestamps) >= max_requests:
        return JSONResponse(status_code=429, content={"detail": "Too many requests"})
    
    timestamps.append(now)
    rate_limit_store[ip] = timestamps
    return await call_next(request)

@app.get("/")
def root():
    return {"message": "Server is up."}

@app.get("/health")
def health():
    return {"status": "ok", "uptime_seconds": time.time() - app.state.start_time}

@app.post("/register")
def register(data: LoginRequest):
    username, password = data.username, data.password
    if is_registered(username):
        return {"status": "already registered"}
    
    password_hash = hash_password(password)
    put_user(username, password_hash)

    return {"status": "registered"}

@app.post("/login")
def login(data: LoginRequest):
    username, password = data.username, data.password
    
    internal_hash = fetch_hash(username)
    
    if not internal_hash or not compare_password(password, internal_hash):
        raise HTTPException(401, "Invalid username or password")
    
    token = generate_token()
    store_token(username, token)

    return {"status" : "ok",
            "token" : token}

@app.post("/logout")
def logout(ses: tuple[str, str] = Depends(get_cur_session)):
    _, token = ses
    delete_token(token)
    return {"status": "logged out"}
    
@app.delete("/deregister")
def deregister(ses: tuple[str, str] = Depends(get_cur_session)):
    user, _ = ses
    delete_user(user)
    return {"status": "account deleted"}
    
@app.get("/secret/nuclear_codes", include_in_schema=False)
async def proxy(ses: tuple[str, str] = Depends(get_cur_session)):
    try: 
        async with httpx.AsyncClient(timeout=httpx.Timeout(2.0), follow_redirects=False) as client:
            upstream = await client.get(f"{INTERNAL_API_URL}/launch-codes",
                                        headers={"X-Internal-Gateway-Auth": GATEWAY_SECRET})
    except httpx.RequestError:
        raise HTTPException(502, "Upstream service unavailable")
    
    if upstream.status_code != 200:
        raise HTTPException(502, "Upstream service error")
    
    data = upstream.json()
    codes = data.get("codes")
    if codes is None:
        raise HTTPException(502, "Malformed upstream response")

    return {
        "intel": codes,
        "classification": "restricted"
    }