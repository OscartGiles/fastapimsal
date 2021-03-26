"""
Basic example of authenticating users with OAuth2 using Microsoft's MSAL library.
Closely based on this Azure sample for Flask https://github.com/Azure-Samples/ms-identity-python-webapp
"""
from typing import Union
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
import fastapiauth

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
fastapiauth.init_auth(app)


# Add home pages
@app.get("/", include_in_schema=False)
async def home(request: Request):

    user = request.session.get("user", None)
    if not user:
        return HTMLResponse('<a href="/login">login</a>')

    return HTMLResponse(
        "<h1>You are signed in</h1> <a href='/docs'>Docs</a> <a href='/redoc'>Redoc</a> <a href='/logout'>Logout</a>"
    )


# Place docs behind auth
@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(
    _: dict = Depends(fastapiauth.logged_in),
) -> Union[JSONResponse, HTMLResponse]:
    """
    Serves OpenAPI endpoints
    """
    return JSONResponse(
        get_openapi(title="Example API", version="0.0.1", routes=app.routes)
    )


@app.get("/docs", include_in_schema=False)
async def get_documentation(_: dict = Depends(fastapiauth.logged_in)) -> HTMLResponse:
    """
    Serves swagger API docs
    """
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")


@app.get("/redoc", include_in_schema=False)
async def get_redocumentation(_: dict = Depends(fastapiauth.logged_in)) -> HTMLResponse:
    """
    Serves redoc API docs
    """
    return get_redoc_html(openapi_url="/openapi.json", title="docs")