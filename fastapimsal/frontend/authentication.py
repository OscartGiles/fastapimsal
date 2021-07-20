"""Authenticate a user using their signed session coookie"""

from typing import Optional, Dict, List, Any
from fastapi import Request
from pydantic import BaseModel

from ..config import get_auth_settings
from ..types import (
    UserId,
    UserIdToken,
    RequiresLoginException,
    LoadCacheCallable,
    SaveCacheCallable,
)
from ..utils import build_msal_app


class UserAuthenticated:
    """Verify a user is signed in by reading the signed session cookie"""

    def __init__(self, auto_error: bool = True):

        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[UserId]:

        user: Optional[str] = request.session.get("user", None)
        if user:
            return UserId(oid=user)

        if self.auto_error:
            raise RequiresLoginException

        return None


class UserAuthenticatedToken(UserAuthenticated):
    """Verify a user is signed in by reading the signed session cookie and silently acquire an access token"""

    def __init__(
        self,
        f_load_cache: LoadCacheCallable,
        f_save_cache: SaveCacheCallable,
        auto_error: bool = True,
    ):

        self.f_load_cache = f_load_cache
        self.f_save_cache = f_save_cache
        self.auto_error = auto_error

        super().__init__(auto_error=False)

    async def get_token_from_cache(
        self, user: UserId, scope: List[str] = None
    ) -> Optional[Dict[Any, Any]]:

        cache = await self.f_load_cache(user.oid)
        cca = build_msal_app(cache=cache)
        accounts = cca.get_accounts()

        if accounts:  # So all account(s) belong to the current signed-in user
            result = cca.acquire_token_silent(scope, account=accounts[0])
            await self.f_save_cache(user.oid, cache)
            return result

        return None

    async def __call__(self, request: Request) -> Optional[UserIdToken]:

        # Verify login
        user = await super().__call__(request=request)

        if user:
            token = await self.get_token_from_cache(user, get_auth_settings().scopes)

            # Verify the token. We just acquired it so should always be valid.
            if token:
                return UserIdToken(oid=user.oid, token=token)

        if self.auto_error:
            raise RequiresLoginException
        return None
