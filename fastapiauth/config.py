"""Configurations"""

from uuid import UUID
from typing import Optional
from pydantic import BaseSettings, HttpUrl, SecretStr
from starlette.middleware.sessions import SessionMiddleware
from fastapi.requests import Request
from fastapi.responses import Response, RedirectResponse


class AuthTokenSettings(BaseSettings):
    """Settings for generating jwt tokens"""

    access_token_secret: SecretStr
    access_token_algorithm: str = "HS256"
    access_token_expire_minutes: int

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


class AuthSettings(BaseSettings):
    """Settings class"""

    client_id: UUID
    client_secret: SecretStr
    tenant_id: UUID
    base_url: Optional[HttpUrl] = "https://login.microsoftonline.com/"
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


AUTH_SETTINGS = AuthSettings()


class UserLogged:
    """Ensure user is logged in"""

    async def __call__(self, request: Request) -> dict:

        user = request.session.get("user")

        print(request.session)
        # print(user)

        if user:
            return user
        raise RequiresLoginException


logged_in = UserLogged()


def init_auth(app, home_name="home"):
    """Add session middleware and an exception handler which redirects to login page"""

    app.add_middleware(
        SessionMiddleware,
        secret_key=AUTH_SETTINGS.session_secret.get_secret_value(),
        max_age=AUTH_SETTINGS.session_expire_time_minutes * 60,
        https_only=AUTH_SETTINGS.https_only,
        session_cookie="home",
    )

    app.add_middleware(
        SessionMiddleware,
        secret_key=AUTH_SETTINGS.session_secret.get_secret_value(),
        max_age=AUTH_SETTINGS.session_expire_time_minutes * 60,
        https_only=AUTH_SETTINGS.https_only,
        session_cookie="clear",
    )

    @app.exception_handler(RequiresLoginException)
    async def exception_handler(
        request: Request, _: RequiresLoginException
    ) -> Response:
        "An exception with redirects to login"
        return RedirectResponse(url=request.url_for(home_name))