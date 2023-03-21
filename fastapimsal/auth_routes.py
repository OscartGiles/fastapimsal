"""
Add routes to a FastAPI application to handle OAuth
"""
import logging
from typing import Dict, List, Optional

import msal
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .config import get_auth_settings
from .frontend.authentication import UserAuthenticated
from .types import RemoveCacheCallable, SaveCacheCallable, UserIdentity
from .utils import build_msal_app

auth_settings = get_auth_settings()
user_authenticated = UserAuthenticated()


def create_auth_router(
    f_save_cache: SaveCacheCallable,
    f_remove_cache: RemoveCacheCallable,
) -> APIRouter:

    router = APIRouter()

    def _auth_uri(request: Request) -> str:

        redirect_uri = str(request.url_for("authorized"))

        if "http://0.0.0.0" in redirect_uri:
            redirect_uri = redirect_uri.replace("http://0.0.0.0", "http://localhost")
        if "http://127.0.0.1" in redirect_uri:
            redirect_uri = redirect_uri.replace("http://127.0.0.1", "http://localhost")

        return redirect_uri

    def _auth_code_flow(
        request: Request,
        authority: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ) -> str:

        flow: Dict[str, str] = build_msal_app(
            authority=authority
        ).initiate_auth_code_flow(
            scopes,
            redirect_uri=_auth_uri(request),
        )
        request.session["flow"] = flow
        return flow["auth_uri"]

    # pylint: disable=W0612
    @router.route("/login", include_in_schema=False)
    async def login(request: Request) -> RedirectResponse:

        flow_uri = _auth_code_flow(request, scopes=get_auth_settings().scopes)

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

            flow = request.session.get("flow", {})
            result = build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
                flow,
                dict(request.query_params),
                scopes=get_auth_settings().scopes,
            )

            # Remove flow cookie
            request.session.pop("flow", None)

            # Just store the oid (https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens) in a signed cookie
            oid = result.get("id_token_claims").get("oid")
            await f_save_cache(oid, cache)
            request.session["user"] = oid
        except ValueError as error:
            logging.debug("%s", error)

        return RedirectResponse(url=request.url_for("home"), status_code=302)

    @router.get("/logout", include_in_schema=False)
    async def logout(
        request: Request,
        user: UserIdentity = Depends(user_authenticated),
    ) -> RedirectResponse:
        """Remove the user from the cache and pop the session cookie.
        Does not sign out of Microsoft
        """
        # Remove user from cache
        if user:
            await f_remove_cache(user.oid)

        # Remove their session cookie
        request.session.pop("user", None)

        return RedirectResponse(url=request.url_for("home"))

    return router
