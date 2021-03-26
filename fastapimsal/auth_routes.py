"""
Authentication with Azure Active Directory
"""
from typing import Any, List
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
import msal
from .config import AuthSettings, logged_in

router = APIRouter()
auth_settings = AuthSettings()


def _build_msal_app(
    cache: Any = None, authority: str = None
) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        str(auth_settings.client_id),
        authority=authority or auth_settings.authority,
        client_credential=auth_settings.client_secret.get_secret_value(),
        token_cache=cache,
    )


def _auth_uri(request: Request) -> str:

    redirect_uri = request.url_for("authorized")

    if "http://0.0.0.0" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://0.0.0.0", "http://localhost")
    if "http://127.0.0.1" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://127.0.0.1", "http://localhost")

    return redirect_uri


def _auth_code_flow(
    request: Request, authority: str = None, scopes: List[str] = None
) -> str:

    flow = _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [], redirect_uri=_auth_uri(request)
    )

    request.session["flow"] = flow

    return flow["auth_uri"]


@router.route("/login", include_in_schema=False)
async def login(request: Request) -> RedirectResponse:

    flow_uri = _auth_code_flow(request)

    return RedirectResponse(url=flow_uri, status_code=302)


@router.get(
    "/getAToken",
    include_in_schema=False,
)  # Its absolute URL must match your app's redirect_uri set in AAD
async def authorized(request: Request) -> RedirectResponse:

    # see https://github.com/Azure-Samples/ms-identity-python-webapp/blob/e342e93a2a7e0cc4d4955c20660e6a81fd2536c5/app.py#L35-L45
    # for try except pattern. Kind of annoying, means you may have to click sign in twice
    try:

        result = _build_msal_app().acquire_token_by_auth_code_flow(
            request.session.get("flow", {}), dict(request.query_params)
        )
        request.session["user"] = result.get("id_token_claims")

    except ValueError:
        pass

    # TODO: Implement a cache for the access token and refresh token so we don't have to get a new token every time.
    # Because we don't check tokens on other routes removing a user from AAD will only take effect when their session cookie expires
    # Session cache should implement a fix.

    # Cache user info on session cookie

    return RedirectResponse(url=request.url_for("home"), status_code=302)


@router.route("/logout", include_in_schema=False)
async def logout(request: Request, _: Any = Depends(logged_in)) -> RedirectResponse:

    request.session.pop("user", None)
    request.session.pop("flow", None)
    return RedirectResponse(url=request.url_for("home"))
