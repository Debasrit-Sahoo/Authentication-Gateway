from fastapi import FastAPI, HTTPException, Depends
from contextlib import asynccontextmanager
from db import init_db, put_user, is_registered, fetch_hash, store_token
from auth import hash_password, compare_password, generate_token
from schemas import LoginRequest
from auth_dependancies import get_cur_user

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("Server booting...")
    print("Tables initialized")

    yield

    print("Server shutting down...")

app = FastAPI(lifespan=lifespan)

@app.get("/")
def root():
    return {"message": "Server is up."}

@app.post("/register")
def register(data: LoginRequest):
    username, password = data.username, data.password
    if is_registered(username):
        raise HTTPException(400, "User is already registered")
    
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
    
@app.get("/secure")
def secure_endpoint(current_user: str = Depends(get_cur_user)):
    return {"user": current_user}