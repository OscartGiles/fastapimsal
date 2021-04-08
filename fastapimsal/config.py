"""Configurations"""

from functools import lru_cache
from uuid import UUID

from pydantic import BaseSettings, HttpUrl, SecretStr


class AuthSettings(BaseSettings):
    """Settings class"""

    client_id: UUID
    client_secret: SecretStr
    tenant_id: UUID
    base_url: HttpUrl = "https://login.microsoftonline.com/"  # type: ignore
    session_secret: SecretStr
    session_expire_time_minutes: int
    https_only: bool = True

    @property
    def authority(self) -> str:
        """Makes authorized URL"""
        return self.base_url + str(self.tenant_id)

    class Config:
        env_file = ".auth.env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_auth_settings() -> AuthSettings:

    return AuthSettings()
