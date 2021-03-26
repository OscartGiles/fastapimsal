from datetime import timedelta, datetime
from jose import JWTError, jwt
from .config import AuthSettings

auth_settings = AuthSettings()

# Define Authentication Routes
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        auth_settings.access_token_secret.get_secret_value(),
        algorithm=auth_settings.access_token_algorithm,
    )
    return encoded_jwt