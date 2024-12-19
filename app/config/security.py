from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.config.utils import verify_token
from app.users.model import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(token: str = Depends(oauth2_scheme)) -> Optional[User]:
    user_email = verify_token(token)
    if user_email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = User.get(User.email == user_email)
    if user:
        user_dict = user.__data__
        user_dict.pop("password", None)
        return user_dict
    return None
