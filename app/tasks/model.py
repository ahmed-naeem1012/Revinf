from app.config.database import BaseModel
from peewee import CharField, FloatField, ForeignKeyField

from app.users.model import User


class Tasks(BaseModel):
    ip = CharField()
    country_name = CharField()
    latitude = FloatField()
    longitude = FloatField()
    flag = CharField()
    continent_code = CharField()
    user = ForeignKeyField(User, backref="ip_data")
