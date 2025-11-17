from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Session, create_engine, select, Relationship
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# -------------------------------
# CONFIGURATION
# -------------------------------
SECRET_KEY = "your_super_secret_key_here"  # 🔒 replace with env var in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="FastAPI + SQLModel + JWT Auth API")

# -------------------------------
# DATABASE SETUP
# -------------------------------
DATABASE_URL = "sqlite:///./database.db"
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})


# -------------------------------
# MODELS
# -------------------------------
class UserEmail(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    email: str
    user: Optional["User"] = Relationship(back_populates="emails")


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    name: str
    age: int
    city: str
    emails: List[UserEmail] = Relationship(back_populates="user")


# -------------------------------
# Pydantic Models (Input / Output)
# -------------------------------
class UserEmailRead(SQLModel):
    email: str


class UserCreate(SQLModel):
    name: str
    age: int
    city: str
    emails: List[str]


class UserRead(SQLModel):
    id: int
    username: str
    name: str
    age: int
    city: str
    emails: List[str]


class UserUpdate(SQLModel):
    name: Optional[str] = None
    age: Optional[int] = None
    city: Optional[str] = None


class UserRegister(SQLModel):
    username: str
    password: str
    name: str
    age: int
    city: str
    emails: List[str]


# -------------------------------
# DATABASE UTILITIES
# -------------------------------
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


def get_session():
    with Session(engine) as session:
        yield session


# -------------------------------
# SECURITY UTILITIES
# -------------------------------
def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# -------------------------------
# AUTH ENDPOINTS
# -------------------------------
@app.post("/register")
def register_user(user_in: UserRegister, session: Session = Depends(get_session)):
    existing_user = session.exec(select(User).where(User.username == user_in.username)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_pw = hash_password(user_in.password)
    user = User(
        username=user_in.username,
        hashed_password=hashed_pw,
        name=user_in.name,
        age=user_in.age,
        city=user_in.city,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # Save emails
    for email in user_in.emails:
        session.add(UserEmail(user_id=user.id, email=email))
    session.commit()

    return {"message": "User registered successfully"}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


# -------------------------------
# PROTECTED CRUD ENDPOINTS
# -------------------------------
@app.get("/users/me", response_model=UserRead)
def read_own_profile(current_user: User = Depends(get_current_user)):
    emails = [email.email for email in current_user.emails]
    return UserRead(
        id=current_user.id,
        username=current_user.username,
        name=current_user.name,
        age=current_user.age,
        city=current_user.city,
        emails=emails,
    )


@app.post("/users/", response_model=UserRead)
def create_user(
    user_in: UserCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    user = User(
        username=f"{user_in.name.lower()}_{int(datetime.utcnow().timestamp())}",
        hashed_password=hash_password("default123"),
        name=user_in.name,
        age=user_in.age,
        city=user_in.city,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    for email in user_in.emails:
        session.add(UserEmail(user_id=user.id, email=email))
    session.commit()

    return UserRead(
        id=user.id,
        username=user.username,
        name=user.name,
        age=user.age,
        city=user.city,
        emails=user_in.emails,
    )


@app.get("/users/", response_model=List[UserRead])
def read_users(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    users = session.exec(select(User)).all()
    results = []
    for user in users:
        emails = [email.email for email in user.emails]
        results.append(
            UserRead(
                id=user.id,
                username=user.username,
                name=user.name,
                age=user.age,
                city=user.city,
                emails=emails,
            )
        )
    return results


@app.get("/users/{user_id}", response_model=UserRead)
def read_user(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    emails = [email.email for email in user.emails]
    return UserRead(**user.dict(), emails=emails)


@app.put("/users/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    user_in: UserUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = user_in.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)

    session.add(user)
    session.commit()
    session.refresh(user)

    emails = [email.email for email in user.emails]
    return UserRead(**user.dict(), emails=emails)


@app.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return None
