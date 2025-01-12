from peewee import CharField, BooleanField, DateTimeField, ForeignKeyField
from app.config.database import BaseModel
from app.users.model import User
from app.servers.model import Server
from app.config.database import BaseModel
from datetime import datetime
import json
from peewee import TextField

class JSONField(TextField):
    def db_value(self, value):
        return json.dumps(value) if value is not None else None

    def python_value(self, value):
        return json.loads(value) if value is not None else None

class UserDomains(BaseModel):
    user = ForeignKeyField(User, backref="domains", on_delete="CASCADE") 
    domain_id = CharField(unique=True)  
    domain = CharField()
    subdomain = CharField()  
    custom_spf = BooleanField(default=True) 
    dns_records = JSONField()  
    server_id = ForeignKeyField(Server, backref="domains", null=True, on_delete="SET NULL")  # Link to Server
    created_at = DateTimeField(default=datetime.utcnow)
