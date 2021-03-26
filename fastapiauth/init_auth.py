from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import Response, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from .config import AuthSettings, RequiresLoginException
from .auth_routes import router as auth_router

AUTH_SETTINGS = AuthSettings()


def init_auth(app: FastAPI, home_name: str = "home") -> None:
    """Initialise the auth

    Args:
        app (FastAPI): [description]
        home_name (str, optional): [description]. Defaults to "home".

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

    # Add routes for logging in and generating access token
    app.include_router(auth_router, tags=["auth"])

    @app.exception_handler(RequiresLoginException)
    async def exception_handler(
        request: Request, _: RequiresLoginException
    ) -> Response:
        "An exception with redirects to login"
        return RedirectResponse(url=request.url_for(home_name))