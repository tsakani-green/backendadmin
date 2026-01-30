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
import motor.motor_asyncio
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import asyncio

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Make oauth2_scheme optional when auth is disabled
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)

# Email sending function
async def send_activation_email(to_email: str, user_name: str, activation_link: str):
    """Send activation email to user"""
    try:
        # Create email content
        subject = "Welcome to AfricaESG.AI - Activate Your Account"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to AfricaESG.AI</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #2E7D32; margin-bottom: 10px;">🌍 Welcome to AfricaESG.AI</h1>
                    <p style="font-size: 18px; color: #666;">Your ESG Dashboard Awaits!</p>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 10px; margin-bottom: 30px;">
                    <h2 style="color: #2E7D32; margin-top: 0;">Hello {user_name},</h2>
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Welcome to AfricaESG.AI! We're excited to have you join our platform for comprehensive ESG monitoring and reporting.
                    </p>
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Your account has been successfully created. To get started, please activate your account by clicking the button below:
                    </p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{activation_link}" 
                           style="background: #2E7D32; color: white; padding: 15px 30px; text-decoration: none; 
                                  border-radius: 5px; font-size: 16px; font-weight: bold; display: inline-block;">
                            🚀 Activate Your Account
                        </a>
                    </div>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 20px;">
                        If the button above doesn't work, you can also copy and paste this link into your browser:<br>
                        <a href="{activation_link}" style="color: #2E7D32;">{activation_link}</a>
                    </p>
                </div>
                
                <div style="background: #e3f2fd; padding: 20px; border-radius: 10px; margin-bottom: 30px;">
                    <h3 style="color: #1976D2; margin-top: 0;">📋 What's Next?</h3>
                    <ol style="font-size: 16px; line-height: 1.8;">
                        <li><strong>Activate your account</strong> using the link above</li>
                        <li><strong>Complete your profile</strong> with additional information</li>
                        <li><strong>Contact your administrator</strong> to get portfolio access assigned</li>
                        <li><strong>Start monitoring</strong> your ESG metrics and carbon emissions</li>
                    </ol>
                </div>
                
                <div style="background: #fff3e0; padding: 20px; border-radius: 10px; margin-bottom: 30px;">
                    <h3 style="color: #f57c00; margin-top: 0;">🔐 Account Security</h3>
                    <p style="font-size: 14px; margin-bottom: 10px;">
                        <strong>Important:</strong> This activation link will expire in 24 hours. If you don't activate your account 
                        within this time, you may need to contact support for assistance.
                    </p>
                    <p style="font-size: 14px;">
                        If you didn't create this account, please ignore this email or contact our support team.
                    </p>
                </div>
                
                <div style="text-align: center; padding: 20px; border-top: 1px solid #eee;">
                    <p style="font-size: 14px; color: #666; margin-bottom: 5px;">
                        <strong>AfricaESG.AI</strong>
                    </p>
                    <p style="font-size: 12px; color: #999;">
                        Live ESG Dashboards + AI-Powered Insights<br>
                        📧 support@africaesg.ai | 🌐 www.africaesg.ai
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
        message["To"] = to_email
        
        # Attach HTML content
        html_part = MIMEText(html_content, "html")
        message.attach(html_part)
        
        # Send email
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()
        server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
        server.send_message(message)
        server.quit()
        
        print(f"Activation email sent successfully to {to_email}")
        
    except Exception as e:
        print(f"Error sending activation email: {str(e)}")
        raise e

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
    role: str  # "admin" or "client"
    company: Optional[str] = None
    disabled: bool = False
    portfolio_access: Optional[list] = []  # List of portfolio IDs user can access
    status: Optional[str] = "active"  # "active", "inactive", "suspended"

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
    portfolio_access: Optional[list] = []  # List of portfolio IDs user can access
    status: Optional[str] = "active"  # "active", "inactive", "suspended"

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

class PasswordResetToken(BaseModel):
    token: str
    user_id: str
    expires_at: datetime
    used: bool = False

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def generate_reset_token():
    return secrets.token_urlsafe(32)

async def send_password_reset_email(email: str, reset_token: str):
    try:
        # For development, we'll just print the reset link
        reset_link = f"http://localhost:5173/reset-password?token={reset_token}"
        print(f"Password reset link for {email}: {reset_link}")
        
        # In production, you would send an actual email:
        # smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        # smtp_server.starttls()
        # smtp_server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
        # 
        # message = MIMEMultipart()
        # message["From"] = settings.EMAIL_USERNAME
        # message["To"] = email
        # message["Subject"] = "Password Reset - AfricaESG.AI"
        # 
        # body = f"""
        # Hello,
        # 
        # You requested a password reset for your AfricaESG.AI account.
        # 
        # Click the link below to reset your password:
        # {reset_link}
        # 
        # This link will expire in 1 hour.
        # 
        # If you didn't request this password reset, please ignore this email.
        # 
        # Best regards,
        # AfricaESG.AI Team
        # """
        # 
        # message.attach(MIMEText(body, "plain"))
        # smtp_server.send_message(message)
        # smtp_server.quit()
        
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

async def authenticate_user(db, username: str, password: str):
    try:
        print(f"Looking for user: {username}")
        # Use a short timeout so frontend doesn't hang if DB is unavailable
        try:
            user = await asyncio.wait_for(
                db.users.find_one({"$or": [{"username": username}, {"email": username}]}),
                timeout=2.0
            )
        except asyncio.TimeoutError:
            print("Database lookup timed out. Falling back to demo users.")
            user = None
        if not user:
            print(f"User not found: {username}")
            # Fallback: allow predefined demo users when DB lookup fails or user not present
            demo_users = {
                "admin": {
                    "password": "admin123",
                    "email": "admin@example.com",
                    "full_name": "Administrator",
                    "role": "admin",
                    "company": "AfricaESG.AI",
                    "portfolio_access": ["dube-trade-port", "bertha-house"],
                },
                "dube-user": {
                    "password": "dube123",
                    "email": "dube@dubetradeport.com",
                    "full_name": "Dube Trade Port Manager",
                    "role": "client",
                    "company": "Dube Trade Port",
                    "portfolio_access": ["dube-trade-port"],
                },
                "bertha-user": {
                    "password": "bertha123",
                    "email": "bertha@berthahouse.com",
                    "full_name": "Bertha House Manager",
                    "role": "client",
                    "company": "Bertha House",
                    "portfolio_access": ["bertha-house"],
                },
            }
            demo = demo_users.get(username)
            if demo and hashlib.sha256(password.encode()).hexdigest() == hashlib.sha256(demo["password"].encode()).hexdigest():
                # Construct a synthetic UserInDB for demo login
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
        
        print(f"User found: {user.get('username')}, verifying password...")
        
        # Import simple hash for verification
        import hashlib
        
        def simple_hash_verify(plain_password, hashed_password):
            """Simple password verification for development"""
            return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password
        
        # Check password using simple hash
        if not simple_hash_verify(password, user["hashed_password"]):
            print(f"Password verification failed for: {username}")
            return False
        
        # Add the _id as id for the UserInDB model
        user_dict = dict(user)
        user_dict['id'] = str(user['_id'])
        
        # Ensure all required fields are present
        user_dict['portfolio_access'] = user_dict.get('portfolio_access', [])
        user_dict['company'] = user_dict.get('company', None)
        user_dict['disabled'] = user_dict.get('disabled', False)
        
        return UserInDB(**user_dict)
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return False

async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    # Skip authentication if disabled
    if not settings.AUTH_ENABLED:
        return UserInDB(
            id="test-user",
            username="test-user",
            email="test@example.com",
            full_name="Test User",
            role="client",
            hashed_password="dummy",
            disabled=False,
            portfolio_access=["dube-trade-port", "bertha-house"]
        )
    
    # If no token provided and auth is enabled, raise exception
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
    
    # Convert _id to id and create UserInDB object
    user_dict = dict(user)
    user_dict['id'] = str(user['_id'])
    
    # Ensure all required fields are present
    user_dict['portfolio_access'] = user_dict.get('portfolio_access', [])
    user_dict['company'] = user_dict.get('company', None)
    user_dict['disabled'] = user_dict.get('disabled', False)
    
    return UserInDB(**user_dict)

@router.post("/signup", response_model=Token)
async def signup(user_data: UserCreate, db = Depends(get_db)):
    try:
        print(f"Signup attempt for username: {user_data.username}, email: {user_data.email}")
        
        # Check if user exists
        existing_user = await db.users.find_one({
            "$or": [
                {"username": user_data.username},
                {"email": user_data.email}
            ]
        })
        
        if existing_user:
            print(f"User already exists: {user_data.username} or {user_data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )
        
        # Hash the password using our simple hash function
        hashed_password = hashlib.sha256(user_data.password.encode()).hexdigest()
        
        user_dict = {
            "username": user_data.username,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "hashed_password": hashed_password,
            "role": "client",
            "company": user_data.company,
            "portfolio_access": user_data.portfolio_access or [],
            "disabled": False,
            "status": user_data.status or "active",
            "created_at": datetime.utcnow()
        }
        
        result = await db.users.insert_one(user_dict)
        user_dict["id"] = str(result.inserted_id)
        
        print(f"User created successfully: {user_data.username}")
        
        # Create access token first
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_data.username, "role": "client"},
            expires_delta=access_token_expires
        )
        
        # Send activation email
        activation_link = f"{settings.FRONTEND_URL}/activate?token={access_token}"
        try:
            await send_activation_email(user_data.email, user_data.full_name, activation_link)
            print(f"Activation email sent to: {user_data.email}")
        except Exception as email_error:
            print(f"Failed to send activation email: {str(email_error)}")
            # Continue with signup even if email fails
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": str(result.inserted_id),
            "role": "client",
            "message": f"Welcome {user_data.full_name}! Your account has been created. Please check your email for activation link."
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Signup error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(get_db)):
    try:
        print(f"Login attempt for username: {form_data.username}")
        # Ensure login doesn't hang indefinitely if DB is down
        try:
            user = await asyncio.wait_for(
                authenticate_user(db, form_data.username, form_data.password),
                timeout=3.0
            )
        except asyncio.TimeoutError:
            print("Authentication timed out; checking demo users")
            user = await authenticate_user(db, form_data.username, form_data.password)
        if not user:
            print(f"Authentication failed for username: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        print(f"Authentication successful for user: {user.username}, role: {user.role}")
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": str(user.id) if hasattr(user, 'id') else "",
            "role": user.role
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.post("/forgot-password")
async def forgot_password(request: PasswordResetRequest, db = Depends(get_db)):
    try:
        print(f"Password reset request for email: {request.email}")
        
        # Find user by email
        user = await db.users.find_one({"email": request.email})
        if not user:
            # Don't reveal that email doesn't exist for security
            print(f"Email not found: {request.email}")
            return {"message": "If the email exists, a reset link has been sent"}
        
        # Generate reset token
        reset_token = generate_reset_token()
        expires_at = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        
        # Store reset token in database
        reset_token_data = {
            "token": reset_token,
            "user_id": str(user["_id"]),
            "email": request.email,
            "expires_at": expires_at,
            "used": False,
            "created_at": datetime.utcnow()
        }
        
        await db.password_reset_tokens.insert_one(reset_token_data)
        
        # Send reset email
        email_sent = await send_password_reset_email(request.email, reset_token)
        
        if email_sent:
            print(f"Password reset email sent to: {request.email}")
            return {"message": "Password reset link sent to your email"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send reset email"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Forgot password error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.post("/reset-password")
async def reset_password(request: PasswordReset, db = Depends(get_db)):
    try:
        print(f"Password reset attempt with token: {request.token[:10]}...")
        
        # Find valid reset token
        reset_token_data = await db.password_reset_tokens.find_one({
            "token": request.token,
            "used": False,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        if not reset_token_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Get user
        user = await db.users.find_one({"_id": ObjectId(reset_token_data["user_id"])})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Hash new password using same method as signup
        hashed_password = hashlib.sha256(request.new_password.encode()).hexdigest()
        
        # Update user password
        await db.users.update_one(
            {"_id": ObjectId(reset_token_data["user_id"])},
            {"$set": {"hashed_password": hashed_password}}
        )
        
        # Mark token as used
        await db.password_reset_tokens.update_one(
            {"_id": reset_token_data["_id"]},
            {"$set": {"used": True}}
        )
        
        print(f"Password reset successful for user: {user.get('username')}")
        
        return {"message": "Password reset successful"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Reset password error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.post("/admin/create-user", response_model=Token)
async def admin_create_user(
    user_data: UserCreate, 
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_db)
):
    """Admin endpoint to create users with specific portfolio access"""
    try:
        # Check if current user is admin
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        print(f"Admin creating user: {user_data.username}, portfolio_access: {user_data.portfolio_access}")
        
        # Check if user exists
        existing_user = await db.users.find_one({
            "$or": [
                {"username": user_data.username},
                {"email": user_data.email}
            ]
        })
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )
        
        # Hash password using same method as signup
        hashed_password = hashlib.sha256(user_data.password.encode()).hexdigest()
        
        user_dict = {
            "username": user_data.username,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "hashed_password": hashed_password,
            "role": "client",
            "company": user_data.company,
            "portfolio_access": user_data.portfolio_access or [],
            "disabled": False,
            "status": user_data.status or "active",
            "created_at": datetime.utcnow()
        }
        
        result = await db.users.insert_one(user_dict)
        user_dict["id"] = str(result.inserted_id)
        
        print(f"Admin created user successfully: {user_data.username}")
        
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_data.username, "role": "client"},
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": str(result.inserted_id),
            "role": "client"
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Admin create user error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.get("/admin/users")
async def admin_get_users(
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_db)
):
    """Admin endpoint to get all users"""
    try:
        # Check if current user is admin
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        users = []
        async for user in db.users.find():
            user_dict = dict(user)
            user_dict['id'] = str(user['_id'])
            # Remove sensitive data and original _id
            user_dict.pop('hashed_password', None)
            user_dict.pop('_id', None)
            users.append(user_dict)
        
        return {"users": users}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Admin get users error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.get("/me")
async def get_current_user_profile(
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get current user profile with portfolio access"""
    try:
        user_dict = {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "role": current_user.role,
            "company": current_user.company,
            "portfolio_access": current_user.portfolio_access or [],
            "disabled": current_user.disabled,
            "status": getattr(current_user, 'status', 'active')
        }
        
        return user_dict
    except Exception as e:
        print(f"Get user profile error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )
