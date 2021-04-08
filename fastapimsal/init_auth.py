from typing import Callable, Optional

import msal
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.sessions import SessionMiddleware

from .auth_routes import RequiresLoginException, create_auth_router
from .config import get_auth_settings

AUTH_SETTINGS = get_auth_settings()


async def default_load_cache(oid: Optional[str] = None) -> None:
    "Function that returns None"

    return None


# pylint: disable=W0613
async def default_save_cache(
    oid: str, cache: Optional[msal.SerializableTokenCache]
) -> None:
    return None


# pylint: disable=W0613
async def default_remove_cache(oid: str) -> None:
    return None


def init_auth(
    app: FastAPI,
    home_name: str = "home",
    f_load_cache: Callable[
        [str], Optional[msal.SerializableTokenCache]
    ] = default_load_cache,
    f_save_cache: Callable[
        [str, Optional[msal.SerializableTokenCache]], None
    ] = default_save_cache,
    f_remove_cache=default_remove_cache,
) -> None:
    """Initialise the auth

    Args:
        app (FastAPI): [description]
        home_name (str, optional): [description]. Defaults to "home".
        load_cache_
    Returns:
        [type]: [description]
    """

    app.add_middleware(
        SessionMiddleware,
        secret_key=AUTH_SETTINGS.session_secret.get_secret_value(),
        max_age=AUTH_SETTINGS.session_expire_time_minutes * 60,
        https_only=AUTH_SETTINGS.https_only,
        session_cookie="session",
    )

    # Add routes for authentiation
    auth_router = create_auth_router(f_load_cache, f_save_cache, f_remove_cache)
    app.include_router(auth_router, tags=["auth"])

    # pylint: disable=W0612
    @app.exception_handler(RequiresLoginException)
    async def exception_handler(
        request: Request, _: RequiresLoginException
    ) -> Response:
        "An exception with redirects to login"
        return RedirectResponse(url=request.url_for(home_name))
