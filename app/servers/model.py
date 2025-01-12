from peewee import CharField, ForeignKeyField, DateTimeField
from app.config.database import BaseModel
from app.users.model import User
from datetime import datetime

class Server(BaseModel):
    Uder = ForeignKeyField(User, backref="servers", on_delete="CASCADE")
    ip_address = CharField(unique=True)
    created_at = DateTimeField(default=datetime.utcnow)
