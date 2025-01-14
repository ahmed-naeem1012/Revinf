from typing import List
from peewee import Model, MySQLDatabase
from decouple import config


class ConfigDatabase:

    database = MySQLDatabase(
        config("DATABASE", default="app"),
        user=config("DATABASE_USERNAME", default="root"),
        password=config("DATABASE_PASSWORD", default=None),
        host=config("DATABASE_HOST", default="127.0.0.1"),
        port=int(config("DATABASE_PORT", default=3306)),
    )

    def __init__(self, models: List[str]):
        self.models = models

    def refresh_tables(self):
        self.database.create_tables(self.models)


class BaseModel(Model):
    class Meta:
        database = ConfigDatabase.database
