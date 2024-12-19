from sqlite3 import IntegrityError
from fastapi import APIRouter, HTTPException, Depends
from app.config.security import get_current_user
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import random
from fastapi_mail import ConnectionConfig
import os
from dotenv import load_dotenv

from datetime import datetime,timedelta
import secrets
from fastapi import Query




from app.users.model import User , OTP
from app.users.schema import LoginSchema, UserSchema
from app.config.utils import (
    create_access_token,
    create_refresh_token,
    get_hashed_password,
    verify_password,
    verify_refresh_token,
)

router_user = APIRouter(prefix="/api/v1")
load_dotenv()


# conf = ConnectionConfig(
#     MAIL_USERNAME="ahmednaeemlhr1012@gmail.com",
#     MAIL_PASSWORD="zecx vifq eufp hpfw",
#     MAIL_FROM="ahmednaeemlhr1012@gmail.com",
#     MAIL_PORT=587,
#     MAIL_SERVER="smtp.gmail.com",
#     MAIL_STARTTLS=True,   # Correct field for STARTTLS
#     MAIL_SSL_TLS=False,   # Correct field for SSL/TLS
#     USE_CREDENTIALS=True,
#     VALIDATE_CERTS=False  # Disable SSL certificate validation

# )


conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS=os.getenv("MAIL_STARTTLS") == "True",
    MAIL_SSL_TLS=os.getenv("MAIL_SSL_TLS") == "True",
    USE_CREDENTIALS=os.getenv("USE_CREDENTIALS") == "True",
    VALIDATE_CERTS=os.getenv("VALIDATE_CERTS") == "True"
)



@router_user.post("/signup")
async def signup(user_data: UserSchema):
    try:
        if User.select().where(User.email == user_data.email).exists():
            raise HTTPException(status_code=400, detail="User already exists")

        # Hash password
        hashed_password = get_hashed_password(user_data.password)

        # Generate verification token
        token = secrets.token_urlsafe(32)
        expiration = datetime.utcnow() + timedelta(hours=24)

        # Create user
        user = User.create(
            first_name=user_data.first_name,
            email=user_data.email,
            password=hashed_password,
            verification_token=token,
            token_expires_at=expiration
        )

        # Generate verification link
        verification_link = f"http://127.0.0.1:8000/api/v1/verify-email?token={token}"

        # Send email with the verification link
        message = MessageSchema(
            subject="Verify Your Email",
            recipients=[user.email],
            body=f"Hello {user.first_name},\n\nPlease click the link below to verify your email:\n{verification_link}\n\nThis link will expire in 24 hours.",
            subtype="plain"
        )
        fm = FastMail(conf)
        await fm.send_message(message)

        return {"message": "Signup successful! Please check your email to verify your account."}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))




@router_user.get("/verify-email")
async def verify_email(token: str = Query(...)):
    try:
        # Find the user with the given token
        user = User.get(User.verification_token == token)

        # Check if the token has expired
        if datetime.utcnow() > user.token_expires_at:
            raise HTTPException(status_code=400, detail="Verification token has expired")

        # Mark the user as verified
        user.is_verified = True
        user.verification_token = None
        user.token_expires_at = None
        user.save()

        return {"message": "Email verified successfully! You can now log in."}

    except User.DoesNotExist:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router_user.post("/auth")
async def auth(user_data: LoginSchema):
    try:
        # Fetch user from database
        user = User.get(User.email == user_data.email)

        # Ensure email is verified
        if not user.is_verified:
            raise HTTPException(status_code=400, detail="Email not verified. Please verify your email to log in.")

        # Verify password
        if not verify_password(user_data.password, user.password):
            raise HTTPException(status_code=400, detail="Invalid password")

        # Generate access and refresh tokens
        access_token = create_access_token(user.email)
        refresh_token = create_refresh_token(user.email)

        return {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router_user.post("/refresh")
async def refresh_tokens(refresh_token: str):
    try:
        email = verify_refresh_token(refresh_token)

        access_token = create_access_token(email)
        new_refresh_token = create_refresh_token(email)

        return {"access_token": access_token, "refresh_token": new_refresh_token}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router_user.get("/user")
async def get_me(user: UserSchema = Depends(get_current_user)):
    return user
