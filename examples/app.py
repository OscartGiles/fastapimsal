"""
Basic example of authenticating users with OAuth2 using Microsoft's MSAL library.
Closely based on this Azure sample for Flask https://github.com/Azure-Samples/ms-identity-python-webapp
"""

from typing import Union
from fastapi import Depends, FastAPI
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

import fastapimsal

# Notice all docs are removed. We can add behind auth later
app = FastAPI(
    title="Example Auth",
    description="Example API with Oauth2 and docs behind auth",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Add session middleware and authentication routes
fastapimsal.init_auth(app)

# Get a callable which checks a user is logged in and raises an HTTPException otherwise
# If we set auto_error=False the exception isn't raised and it returns None
user_authenticated = fastapimsal.frontend.UserAuthenticated(auto_error=True)

# Not raising an error can be useful if you want to return different content depending on whether a user is authenticated
user_authenticated_no_error = fastapimsal.frontend.UserAuthenticated(auto_error=False)


# Add home pages
@app.get("/", include_in_schema=False)
async def home(
    user: fastapimsal.UserIdentity = Depends(user_authenticated_no_error),
) -> HTMLResponse:

    if not user:
        return HTMLResponse('<a href="/login">login</a>')

    return HTMLResponse(
        "<h1>You are signed in</h1> <a href='/docs'>Docs</a> <a href='/redoc'>Redoc</a> <a href='/logout'>Logout</a>"
    )


# Place docs behind auth which will error
@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(
    _: fastapimsal.UserIdentity = Depends(user_authenticated),
) -> Union[JSONResponse, HTMLResponse]:
    """
    Serves OpenAPI endpoints
    """
    return JSONResponse(
        get_openapi(title="Example API", version="0.0.1", routes=app.routes)
    )


@app.get("/docs", include_in_schema=False)
async def get_documentation(
    _: fastapimsal.UserIdentity = Depends(user_authenticated),
) -> HTMLResponse:
    """
    Serves swagger API docs
    """
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")


@app.get("/redoc", include_in_schema=False)
async def get_redocumentation(
    _: fastapimsal.UserIdentity = Depends(user_authenticated),
) -> HTMLResponse:
    """
    Serves redoc API docs
    """
    return get_redoc_html(openapi_url="/openapi.json", title="docs")


# @app.get("/apipath")
# def callme(user: Dict[str, Any] = Depends(token_verified)) -> str:
#     """An example API route"""

#     if user:
#         return f"Welcome {user['preferred_username']}"

#     return "Welcome - you aren't authorized. You only got here because auto_error was set to False"
