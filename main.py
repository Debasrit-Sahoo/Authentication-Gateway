from fastapi import FastAPI, HTTPException, Depends, Request
import time
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from db import init_db, put_user, is_registered, fetch_hash, store_token, delete_token, delete_user
from auth import hash_password, compare_password, generate_token
from schemas import LoginRequest
from auth_dependancies import get_cur_session

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

@app.middleware("http")
async def rate_limiter(request: Request, call_next):
    ip = request.client
    ip = ip.host if ip else "unknown"
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
    
@app.get("/me")
def me(ses: tuple[str, str] = Depends(get_cur_session)):
    user, _ = ses
    return {"user": user}