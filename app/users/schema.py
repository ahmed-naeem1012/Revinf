from pydantic import BaseModel
from pydantic import BaseModel, EmailStr, Field
from peewee import CharField, DateTimeField
from datetime import datetime


# class UserSchema(BaseModel):
#     first_name: str
#     last_name: str
#     email: str
#     password: str

#     class Config:
#         json_schema_extra = {
#             "example": {
#                 "first_name": "Zaman",
#                 "last_name": "Kazimov",
#                 "email": "kazimovzaman2@gmail.com",
#                 "password": "password",
#             }
#         }

class UserSchema(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    

class LoginSchema(BaseModel):
    email: str
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "email": "kazimovzaman2@gmail.com",
                "password": "password",
            }
        }


