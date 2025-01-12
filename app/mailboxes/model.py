from peewee import CharField, BooleanField, DateTimeField, ForeignKeyField
from app.config.database import BaseModel
from app.users.model import User
from app.domains.model import UserDomains
from datetime import datetime

class Mailbox(BaseModel):
    user = ForeignKeyField(User, backref="mailboxes", on_delete="CASCADE")
    domain = ForeignKeyField(UserDomains, backref="mailboxes", on_delete="CASCADE")
    mailbox_id = CharField(unique=True)
    nickname = CharField()
    from_email = CharField()
    from_name = CharField()
    reply_to_email = CharField()
    reply_to_name = CharField()
    address = CharField()
    address_2 = CharField(null=True)
    city = CharField()
    state = CharField()
    zip_code = CharField()
    country = CharField()
    verified_status = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
