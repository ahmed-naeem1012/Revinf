from app.config.database import BaseModel
from peewee import CharField, BooleanField
from peewee import CharField, ForeignKeyField, DateTimeField
from datetime import datetime, timedelta



class User(BaseModel):
    first_name = CharField()
    email = CharField(unique=True)
    password = CharField()
    is_verified = BooleanField(default=False)  # Indicates email verification status
    verification_token = CharField(null=True)  # Token for email verification
    token_expires_at = DateTimeField(null=True)  # Expiration for the verification token



class OTP(BaseModel):
    user = ForeignKeyField(User, backref="otps", on_delete="CASCADE")
    code = CharField()  # Store the 6-digit OTP
    expires_at = DateTimeField(default=lambda: datetime.utcnow() + timedelta(minutes=5))