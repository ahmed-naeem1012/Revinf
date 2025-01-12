from app.config.database import BaseModel
from peewee import CharField, BooleanField
from peewee import ForeignKeyField, CharField, BooleanField, DateTimeField
import json
from datetime import datetime, timedelta
from peewee import TextField



class JSONField(TextField):
    def db_value(self, value):
        return json.dumps(value) if value is not None else None

    def python_value(self, value):
        return json.loads(value) if value is not None else None

class User(BaseModel):
    first_name = CharField()
    email = CharField(unique=True)
    password = CharField()
    is_verified = BooleanField(default=False) 
    verification_token = CharField(null=True) 
    token_expires_at = DateTimeField(null=True)  


class Server(BaseModel):
    Uder = ForeignKeyField(User, backref="servers", on_delete="CASCADE")
    ip_address = CharField(unique=True)
    created_at = DateTimeField(default=datetime.utcnow)



class OTP(BaseModel):
    user = ForeignKeyField(User, backref="otps", on_delete="CASCADE")
    code = CharField()  
    expires_at = DateTimeField(default=lambda: datetime.utcnow() + timedelta(minutes=5))


class UserServer(BaseModel):
    user = ForeignKeyField(User, backref="servers", on_delete="CASCADE")
    ip = CharField() 
    created_at = DateTimeField(default=datetime.utcnow)

class Server(BaseModel):
    ip_address = CharField(unique=True) 
    created_at = DateTimeField(default=datetime.utcnow) 


class UserDomains(BaseModel):
    user = ForeignKeyField(User, backref="domains", on_delete="CASCADE") 
    domain_id = CharField(unique=True)  
    domain = CharField()
    subdomain = CharField()  
    custom_spf = BooleanField(default=True) 
    dns_records = JSONField()  
    server_id = ForeignKeyField(Server, backref="domains", null=True, on_delete="SET NULL")  # Link to Server
    created_at = DateTimeField(default=datetime.utcnow) 

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
