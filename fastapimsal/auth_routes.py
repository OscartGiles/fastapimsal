"""
Authentication with Azure Active Directory
"""
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Union

import msal
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .config import get_auth_settings

auth_settings = get_auth_settings()


class RequiresLoginException(Exception):
    """Exception to raise when login required"""


class UserLogged:
    """Ensure user is logged in"""

    async def __call__(self, request: Request) -> dict:

        user = request.session.get("user", None)
        if user:
            return user
        raise RequiresLoginException


def build_msal_app(
    cache: Optional[msal.SerializableTokenCache] = None, authority: str = None
) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        str(auth_settings.client_id),
        authority=authority or auth_settings.authority,
        client_credential=auth_settings.client_secret.get_secret_value(),
        token_cache=cache,
    )


class UserLoggedValidated:
    """Ensure user is logged in"""

    def __init__(
        self,
        f_load_cache: Callable[[str], Optional[msal.SerializableTokenCache]],
        f_save_cache: Callable[[str, Optional[msal.SerializableTokenCache]], None],
    ):

        self.f_load_cache = f_load_cache
        self.f_save_cache = f_save_cache

    async def get_token_from_cache(
        self, oid, scope: List[str] = None
    ) -> Optional[Dict[Any, Any]]:
        cache = await self.f_load_cache(
            oid
        )  # This web app maintains one cache per session
        print("check", cache)
        cca = build_msal_app(cache=cache)
        accounts = cca.get_accounts()

        print(scope)
        if accounts:  # So all account(s) belong to the current signed-in user
            result = cca.acquire_token_silent(scope, account=accounts[0])
            await self.f_save_cache(oid, cache)
            return result

        return None

    async def __call__(self, request: Request) -> Dict:

        oid = request.session.get("user", None)
        if oid:
            token = await self.get_token_from_cache(oid, [])
            # ToDo: Do I need to validate the token again?
            if token:
                return oid
        raise RequiresLoginException


@lru_cache()
def f_logged_in(
    f_load_cache: Callable[[str], Optional[msal.SerializableTokenCache]] = None,
    f_save_cache: Callable[[str, Optional[msal.SerializableTokenCache]], None] = None,
    validate: bool = False,
) -> Union[UserLoggedValidated, UserLogged]:

    if validate and f_load_cache and f_save_cache:
        return UserLoggedValidated(f_load_cache, f_save_cache)

    if validate:
        raise ValueError(
            "You must provide f_load_cache and f_save_cache if validate is True"
        )

    return UserLogged()


def create_auth_router(
    f_load_cache: Callable[[Optional[str]], Optional[msal.SerializableTokenCache]],
    f_save_cache: Callable[[str, Optional[msal.SerializableTokenCache]], None],
    f_remove_cache,
) -> APIRouter:

    router = APIRouter()

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

        flow = build_msal_app(authority=authority).initiate_auth_code_flow(
            scopes or [], redirect_uri=_auth_uri(request)
        )

        request.session["flow"] = flow

        return flow["auth_uri"]

    # pylint: disable=W0612
    @router.route("/login", include_in_schema=False)
    async def login(request: Request) -> RedirectResponse:

        flow_uri = _auth_code_flow(request)

        return RedirectResponse(url=flow_uri, status_code=302)

    # pylint: disable=W0612
    @router.get(
        "/getAToken",
        include_in_schema=False,
    )  # Its absolute URL must match your app's redirect_uri set in AAD
    async def authorized(request: Request) -> RedirectResponse:

        # see https://github.com/Azure-Samples/ms-identity-python-webapp/blob/e342e93a2a7e0cc4d4955c20660e6a81fd2536c5/app.py#L35-L45
        # for try except pattern. Kind of annoying, means you may have to click sign in twice
        try:
            cache = msal.SerializableTokenCache()
            result = build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
                request.session.get("flow", {}), dict(request.query_params)
            )

            # Just store the oid (https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens) in a signed cookie
            oid = result.get("id_token_claims").get("oid")
            await f_save_cache(oid, cache)
            request.session["user"] = oid

        except ValueError as e:
            print(e)

        return RedirectResponse(url=request.url_for("home"), status_code=302)

    # pylint: disable=W0612
    @router.route("/logout", include_in_schema=False)
    async def logout(
        request: Request, _: Any = Depends(f_logged_in)
    ) -> RedirectResponse:

        oid = request.session.pop("user", None)
        await f_remove_cache(oid)

        request.session.pop("flow", None)
        return RedirectResponse(url=request.url_for("home"))

    return router
