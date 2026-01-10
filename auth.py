import bcrypt, secrets

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def compare_password(password: str, internal_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), internal_hash)

def generate_token() -> str:
    return secrets.token_urlsafe(64)