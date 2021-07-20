from typing import Callable, Awaitable, Optional, Dict, Any
import msal
from pydantic import BaseModel


LoadCacheCallable = Callable[[str], Awaitable[msal.SerializableTokenCache]]
SaveCacheCallable = Callable[[str, msal.SerializableTokenCache], Awaitable[None]]
RemoveCacheCallable = Callable[[str], Awaitable[None]]


class UserId(BaseModel):
    """User identity.

    An OID is a unique user identify in Mirosoft Identity Platform

    https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
    """

    oid: str


class UserIdToken(UserId):

    token: Dict[str, Any]


UserIdentity = Optional[UserId]
UserIdentityToken = Optional[UserIdToken]


class RequiresLoginException(Exception):
    """User not logged in"""
