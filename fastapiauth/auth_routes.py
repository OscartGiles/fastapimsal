"""
Authentication with Azure Active Directory
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
import msal
from .config import AuthSettings, logged_in

router = APIRouter()
auth_settings = AuthSettings()


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        str(auth_settings.client_id),
        authority=authority or auth_settings.authority,
        client_credential=auth_settings.client_secret.get_secret_value(),
        token_cache=cache,
    )


def _auth_uri(request: Request):

    redirect_uri = request.url_for("authorized")

    if "http://0.0.0.0" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://0.0.0.0", "http://localhost")
    if "http://127.0.0.1" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://127.0.0.1", "http://localhost")

    return redirect_uri


def _auth_code_flow(request: Request, authority=None, scopes=None):

    flow = _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [], redirect_uri=_auth_uri(request)
    )
    request.session["flow"] = flow

    return flow["auth_uri"]


@router.route("/login", include_in_schema=False)
async def login(request: Request):

    flow_uri = _auth_code_flow(request)

    return RedirectResponse(url=flow_uri)


@router.get(
    "/getAToken",
    include_in_schema=False,
)  # Its absolute URL must match your app's redirect_uri set in AAD
async def authorized(request: Request):

    result = _build_msal_app().acquire_token_by_auth_code_flow(
        request.session.get("flow", {}), dict(request.query_params)
    )

    # ToDo: Implement a cache for the access token and refresh token so we don't have to get a new token every time.
    # Because we don't check tokens on other routes removing a user from AAD will only take effect when their session cookie expires
    # Session cache should implement a fix.

    # Cache user info on session cookie
    request.session["user"] = result.get("id_token_claims")

    return RedirectResponse(url=request.url_for("dash"))


@router.route("/logout", include_in_schema=False)
async def logout(request: Request, _=Depends(logged_in)):

    request.session.pop("user", None)
    # request.session.pop("tokens", None)
    return RedirectResponse(url=request.url_for("home"))
