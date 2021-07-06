"""Validate JWT from Azure"""


from typing import Optional, Dict, List, Any
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
import httpx
import msal
from async_lru import alru_cache

from .config import get_auth_settings
from .types import LoadCacheCallable, SaveCacheCallable

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authorized. Token was invalid",
    headers={"WWW-Authenticate": "Bearer"},
)


def check_issuer(issuer: str) -> str:
    if issuer != get_auth_settings().issuer:
        raise HTTPException(
            status_code=401, detail=f"Unrecognised issuer {issuer} in token"
        )
    return issuer


@alru_cache()
async def get_key_uri() -> str:

    token_meta_data_uri = get_auth_settings().token_metadata_uri
    async with httpx.AsyncClient() as client:
        res = await client.get(token_meta_data_uri)

    key_uri = res.json()["jwks_uri"]
    return key_uri


@alru_cache()
async def get_key(key_id: str) -> str:

    key_uri = await get_key_uri()
    async with httpx.AsyncClient() as client:
        res = await client.get(key_uri)

    all_keys = res.json()["keys"]
    decoded_key = next(filter(lambda x: x["kid"] == key_id, all_keys), None)

    if not decoded_key:
        raise HTTPException(status_code=401, detail="Unrecognised kid in token")
    return decoded_key


def build_msal_app(
    cache: Optional[msal.SerializableTokenCache] = None, authority: str = None
) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        str(get_auth_settings().client_id),
        authority=authority or get_auth_settings().authority,
        client_credential=get_auth_settings().client_secret.get_secret_value(),
        token_cache=cache,
    )


class RequiresLoginException(Exception):
    """Exception to raise when login required"""


class UserLogged:
    """Ensure user is logged in by checking the session cookie"""

    async def __call__(self, request: Request) -> str:

        user: Optional[str] = request.session.get("user", None)
        if user:
            return user
        raise RequiresLoginException


async def verify_access_token(token: str, auto_error=True) -> Optional[Dict[str, Any]]:

    # If token has incorrect format
    if not token and auto_error:
        raise CREDENTIALS_EXCEPTION

    try:
        unverified_headers = jwt.get_unverified_header(token)
        unverified_claims = jwt.get_unverified_claims(token)
        kid = unverified_headers.get("kid")

        # Verify the issuer
        check_issuer(unverified_claims["iss"])
        decoded_key = await get_key(kid)

        token_decoded = jwt.decode(
            token,
            decoded_key,
            algorithms=unverified_headers["alg"],
            audience=str(get_auth_settings().client_id),
        )
    except JWTError:
        if auto_error:
            raise CREDENTIALS_EXCEPTION
        return None

    return token_decoded


class UserLoggedTokenVerified:
    """Ensure a user is logged in and return an access token. Use if you need the acccess token.
    The access token is validated.

    Gets the users oid from the session cookie and then
    returns an access token. First looks in the cache, but will acquire a new token if not valid
    """

    def __init__(
        self,
        f_load_cache: LoadCacheCallable,
        f_save_cache: SaveCacheCallable,
        auto_error: bool = True,
    ):

        self.f_load_cache = f_load_cache
        self.f_save_cache = f_save_cache
        self.auto_error = auto_error

    async def get_token_from_cache(
        self, oid: str, scope: List[str] = None
    ) -> Optional[Dict[Any, Any]]:

        cache = await self.f_load_cache(oid)
        cca = build_msal_app(cache=cache)
        accounts = cca.get_accounts()

        if accounts:  # So all account(s) belong to the current signed-in user
            result = cca.acquire_token_silent(scope, account=accounts[0])
            await self.f_save_cache(oid, cache)
            return result

        return None

    # ToDO: Should add types to the return type (even deserialize to dataclass)
    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """Return a validated token from the cache if a user is logged in (has session cookie)."""
        oid: Optional[str] = request.session.get("user", None)
        if oid:
            token = await self.get_token_from_cache(oid, get_auth_settings().scopes)

            # Verify the token. We just acquired it so should always be valid.
            if token:
                return await verify_access_token(
                    token["access_token"], auto_error=self.auto_error
                )
        if self.auto_error:
            raise RequiresLoginException
        return None


class TokenVerifier:
    def __init__(
        self,
        auto_error: bool = True,
    ):
        self.auto_error = auto_error

    async def __call__(
        self, token: str = Depends(oauth2_scheme)
    ) -> Optional[Dict[str, Any]]:

        return await verify_access_token(token, auto_error=self.auto_error)
