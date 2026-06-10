from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = "cyberwatch-siem-secret-key-2024-university-project"
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)

def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def hash_password(password):        return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        return {"username": "demo", "role": "Administrator"}
    payload = decode_token(token)
    if not payload:
        return {"username": "demo", "role": "Administrator"}
    return {"username": payload.get("sub"), "role": payload.get("role", "SOC Analyst")}
