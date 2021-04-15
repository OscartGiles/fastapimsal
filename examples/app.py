"""
Basic example of authenticating users with OAuth2 using Microsoft's MSAL library.
Closely based on this Azure sample for Flask https://github.com/Azure-Samples/ms-identity-python-webapp
"""
from typing import Union

from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

import fastapimsal

# Notice all docs are removed. We can add behind auth later
app = FastAPI(
    title="Example Auth",
    description="Example API with Oauth2 and docs behind auth",
    version="0.0.1",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Add session middleware and authentication routes
fastapimsal.init_auth(app)
logged_in = fastapimsal.f_logged_in(validate=False)
# Set auto_error=False to not raise a validation error and token will return None
token_verified = fastapimsal.TokenVerifier(auto_error=True)

# Add home pages
@app.get("/", include_in_schema=False)
async def home(request: Request) -> HTMLResponse:

    user = request.session.get("user", None)
    if not user:
        return HTMLResponse('<a href="/login">login</a>')

    return HTMLResponse(
        "<h1>You are signed in</h1> <a href='/docs'>Docs</a> <a href='/redoc'>Redoc</a> <a href='/logout'>Logout</a>"
    )


# Place docs behind auth
@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(
    _: dict = Depends(logged_in),
) -> Union[JSONResponse, HTMLResponse]:
    """
    Serves OpenAPI endpoints
    """
    return JSONResponse(
        get_openapi(title="Example API", version="0.0.1", routes=app.routes)
    )


@app.get("/docs", include_in_schema=False)
async def get_documentation(_: dict = Depends(logged_in)) -> HTMLResponse:
    """
    Serves swagger API docs
    """
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")


@app.get("/redoc", include_in_schema=False)
async def get_redocumentation(
    _: dict = Depends(logged_in),
) -> HTMLResponse:
    """
    Serves redoc API docs
    """
    return get_redoc_html(openapi_url="/openapi.json", title="docs")


@app.get("/apipath")
def callme(user=Depends(token_verified)):
    """An example API route"""

    if user:
        return f"Welcome {user['preferred_username']}"

    return f"Welcome - you aren't authorised. You only got here because auto_error was set to False"
