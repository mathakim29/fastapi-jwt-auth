from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from typing import Annotated
from nanoid import generate
import duckdb

SECRET_KEY = "supersecret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
ph = PasswordHasher()
user_db = duckdb.connect("database/users.db")

refresh_tokens = {}  # In-memory refresh store


# ------------------------ Models ------------------------
class User(BaseModel):
    id: str
    username: str
    full_name: str | None = None
    email: EmailStr | None = None
    disabled: bool = False

class UserInDB(User):
    hashed_password: str


# ------------------------ Utils ------------------------
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(con, username: str) -> UserInDB | None:
    row = con.execute("SELECT * FROM users WHERE username = ?", [username]).fetchone()
    if not row:
        return None
    return UserInDB(**dict(zip([c[0] for c in con.description], row)))

def get_all_users() -> list[UserInDB]:
    rows = user_db.execute("SELECT * FROM users").fetchall()
    if not rows:
        return []
    columns = [col[0] for col in user_db.description]
    return [UserInDB(**dict(zip(columns, row))) for row in rows]

def authenticate_user(con, username: str, password: str):
    user = get_user(con, username)
    if not user:
        return False
    try:
        ph.verify(user.hashed_password, password)
        return user
    except:
        return False

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user(user_db, username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def is_admin(user: User):
    return user.username == "admin"


# ------------------------ Endpoints ------------------------
@app.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(user_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_access_token({"sub": user.username}, timedelta(days=7))
    refresh_tokens[user.username] = refresh_token
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@app.post("/tokens/refresh")
async def refresh_token_endpoint(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username or refresh_tokens.get(username) != token:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        new_access_token = create_access_token({"sub": username})
        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/users/current", response_model=User)
async def read_current_user(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

@app.get("/users/all", response_model=list[User])
async def read_all_users(current_user: Annotated[User, Depends(get_current_user)]):
    if not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Only admin can view all users")
    return get_all_users()

@app.post("/users/create", response_model=User)
async def create_new_user(
    username: str,
    password: str,
    current_user: Annotated[User, Depends(get_current_user)],
    full_name: str | None = None,
    email: EmailStr | None = None,
):
    if not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Only admin can create users")
    if get_user(user_db, username):
        raise HTTPException(status_code=400, detail="Username already registered")
    user_id = generate()
    hashed_pw = ph.hash(password)
    user_db.execute(
        "INSERT INTO users (id, username, full_name, email, hashed_password, disabled) VALUES (?, ?, ?, ?, ?, FALSE)",
        [user_id, username, full_name, email, hashed_pw],
    )
    return get_user(user_db, username)

@app.post("/users/reset-db")
def reset_db():
    user_db.execute("DROP TABLE IF EXISTS users")
    user_db.execute("""
        CREATE TABLE users (
            id TEXT,
            username TEXT,
            full_name TEXT,
            email TEXT,
            hashed_password TEXT,
            disabled BOOLEAN
        )
    """)
    admin_id = generate()
    hashed_pw = ph.hash("admin")
    user_db.execute(
        "INSERT INTO users VALUES (?, 'admin', 'Admin User', 'admin@example.com', ?, FALSE)",
        [admin_id, hashed_pw],
    )
    return {"status": "reset complete"}
