"""Configurations"""

from uuid import UUID
from typing import Optional
from pydantic import BaseSettings, HttpUrl, SecretStr
from fastapi.requests import Request
from fastapi.responses import Response, RedirectResponse


class AuthSettings(BaseSettings):
    """Settings class"""

    client_id: UUID
    client_secret: SecretStr
    tenant_id: UUID
    base_url: HttpUrl = "https://login.microsoftonline.com/"
    session_secret: SecretStr
    session_expire_time_minutes: int
    https_only: bool = True

    @property
    def authority(self) -> str:
        """Makes authorized URL"""
        return self.base_url + str(self.tenant_id)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


class RequiresLoginException(Exception):
    """Exception to raise when login required"""

    pass


class UserLogged:
    """Ensure user is logged in"""

    async def __call__(self, request: Request) -> dict:

        user = request.session.get("user", None)
        if user:
            return user
        raise RequiresLoginException


logged_in = UserLogged()
