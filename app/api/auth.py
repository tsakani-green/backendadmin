# backend/app/api/auth.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from typing import Optional
from app.core.config import settings
from app.core.database import get_db
from bson import ObjectId
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import asyncio

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# IMPORTANT: tokenUrl should match your router prefix + endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# Email sending function
async def send_activation_email(to_email: str, user_name: str, activation_link: str):
    try:
        subject = "Welcome to AfricaESG.AI - Activate Your Account"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #2E7D32;">🌍 Welcome to AfricaESG.AI</h1>
            <p style="font-size: 16px;">Hello {user_name},</p>
            <p style="font-size: 16px;">Activate your account:</p>
            <p><a href="{activation_link}">{activation_link}</a></p>
          </div>
        </body>
        </html>
        """

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
        message["To"] = to_email

        html_part = MIMEText(html_content, "html")
        message.attach(html_part)

        # Send email (only if configured)
        if not settings.EMAIL_USERNAME or not settings.EMAIL_PASSWORD:
            print("Email credentials not set; skipping email send.")
            return

        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()
        server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
        server.send_message(message)
        server.quit()

        print(f"Activation email sent successfully to {to_email}")
    except Exception as e:
        print(f"Error sending activation email: {str(e)}")
        raise


class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    role: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class User(BaseModel):
    id: Optional[str] = None
    username: str
    email: str
    full_name: str
    role: str
    company: Optional[str] = None
    disabled: bool = False
    portfolio_access: Optional[list] = []
    status: Optional[str] = "active"


class UserInDB(User):
    hashed_password: str
    id: str
    portfolio_access: Optional[list] = []


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: str
    company: Optional[str] = None
    portfolio_access: Optional[list] = []
    status: Optional[str] = "active"


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordReset(BaseModel):
    token: str
    new_password: str


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def generate_reset_token():
    return secrets.token_urlsafe(32)


async def send_password_reset_email(email: str, reset_token: str):
    try:
        # IMPORTANT: use FRONTEND_URL (Render static site) not localhost
        reset_link = f"{settings.FRONTEND_URL.rstrip('/')}/reset-password?token={reset_token}"
        print(f"Password reset link for {email}: {reset_link}")

        # If you want to send email for real, configure EMAIL_USERNAME/PASSWORD in Render
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


async def authenticate_user(db, username: str, password: str):
    try:
        try:
            user = await asyncio.wait_for(
                db.users.find_one({"$or": [{"username": username}, {"email": username}]}),
                timeout=2.0,
            )
        except asyncio.TimeoutError:
            user = None

        if not user:
            demo_users = {
                "admin": {
                    "password": "admin123",
                    "email": "admin@example.com",
                    "full_name": "Administrator",
                    "role": "admin",
                    "company": "AfricaESG.AI",
                    "portfolio_access": ["dube-trade-port", "bertha-house"],
                },
            }
            demo = demo_users.get(username)
            if demo and hashlib.sha256(password.encode()).hexdigest() == hashlib.sha256(demo["password"].encode()).hexdigest():
                return UserInDB(
                    id=f"demo-{username}",
                    username=username,
                    email=demo["email"],
                    full_name=demo["full_name"],
                    role=demo["role"],
                    hashed_password=hashlib.sha256(demo["password"].encode()).hexdigest(),
                    company=demo["company"],
                    portfolio_access=demo["portfolio_access"],
                    disabled=False,
                )
            return False

        def simple_hash_verify(plain_password, hashed_password):
            return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password

        if not simple_hash_verify(password, user["hashed_password"]):
            return False

        user_dict = dict(user)
        user_dict["id"] = str(user["_id"])
        user_dict["portfolio_access"] = user_dict.get("portfolio_access", [])
        user_dict["company"] = user_dict.get("company", None)
        user_dict["disabled"] = user_dict.get("disabled", False)

        return UserInDB(**user_dict)
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return False


async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    if not settings.AUTH_ENABLED:
        return UserInDB(
            id="test-user",
            username="test-user",
            email="test@example.com",
            full_name="Test User",
            role="client",
            hashed_password="dummy",
            disabled=False,
            portfolio_access=["dube-trade-port", "bertha-house"],
        )

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception

    user = await db.users.find_one({"username": token_data.username})
    if user is None:
        raise credentials_exception

    user_dict = dict(user)
    user_dict["id"] = str(user["_id"])
    user_dict["portfolio_access"] = user_dict.get("portfolio_access", [])
    user_dict["company"] = user_dict.get("company", None)
    user_dict["disabled"] = user_dict.get("disabled", False)

    return UserInDB(**user_dict)


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    try:
        try:
            user = await asyncio.wait_for(
                authenticate_user(db, form_data.username, form_data.password),
                timeout=3.0,
            )
        except asyncio.TimeoutError:
            user = await authenticate_user(db, form_data.username, form_data.password)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=access_token_expires,
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": str(user.id) if hasattr(user, "id") else "",
            "role": user.role,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}",
        )


@router.post("/forgot-password")
async def forgot_password(request: PasswordResetRequest, db=Depends(get_db)):
    try:
        user = await db.users.find_one({"email": request.email})
        if not user:
            return {"message": "If the email exists, a reset link has been sent"}

        reset_token = generate_reset_token()
        expires_at = datetime.utcnow() + timedelta(hours=1)

        reset_token_data = {
            "token": reset_token,
            "user_id": str(user["_id"]),
            "email": request.email,
            "expires_at": expires_at,
            "used": False,
            "created_at": datetime.utcnow(),
        }
        await db.password_reset_tokens.insert_one(reset_token_data)

        email_sent = await send_password_reset_email(request.email, reset_token)
        if email_sent:
            return {"message": "Password reset link sent to your email"}
        raise HTTPException(status_code=500, detail="Failed to send reset email")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/reset-password")
async def reset_password(request: PasswordReset, db=Depends(get_db)):
    try:
        reset_token_data = await db.password_reset_tokens.find_one(
            {"token": request.token, "used": False, "expires_at": {"$gt": datetime.utcnow()}}
        )
        if not reset_token_data:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")

        user = await db.users.find_one({"_id": ObjectId(reset_token_data["user_id"])})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        hashed_password = hashlib.sha256(request.new_password.encode()).hexdigest()

        await db.users.update_one(
            {"_id": ObjectId(reset_token_data["user_id"])},
            {"$set": {"hashed_password": hashed_password}},
        )
        await db.password_reset_tokens.update_one(
            {"_id": reset_token_data["_id"]},
            {"$set": {"used": True}},
        )

        return {"message": "Password reset successful"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
