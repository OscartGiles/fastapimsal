"""Authenticate a user by verifying a JWT"""

from typing import Any, Dict, List, Optional

import httpx
from async_lru import alru_cache
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from ..config import get_auth_settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authorized. Token was invalid",
    headers={"WWW-Authenticate": "Bearer"},
)


class TokenVerifier:
    def __init__(
        self,
        auto_error: bool = True,
    ):
        self.auto_error = auto_error

    def check_issuer(self, issuer: str) -> str:
        if issuer != get_auth_settings().issuer:
            raise HTTPException(
                status_code=401, detail=f"Unrecognized issuer {issuer} in token"
            )
        return issuer

    @alru_cache()
    async def get_key_uri(self) -> str:

        token_meta_data_uri = get_auth_settings().token_metadata_uri
        async with httpx.AsyncClient() as client:
            res = await client.get(token_meta_data_uri)

        key_uri: str = res.json()["jwks_uri"]
        return key_uri

    @alru_cache()
    async def get_key(self, key_id: str) -> Dict[str, str]:

        key_uri = await self.get_key_uri()
        async with httpx.AsyncClient() as client:
            res = await client.get(key_uri)

        all_keys: List[Dict[str, str]] = res.json()["keys"]

        decoded_key = next(filter(lambda x: x["kid"] == key_id, all_keys), None)

        if not decoded_key:
            raise HTTPException(status_code=401, detail="Unrecognized kid in token")
        return decoded_key

    async def verify_access_token(
        self, token: str, auto_error: bool = True
    ) -> Optional[Dict[str, Any]]:

        # If token has incorrect format
        if not token and auto_error:
            raise CREDENTIALS_EXCEPTION

        try:
            unverified_headers = jwt.get_unverified_header(token)
            unverified_claims = jwt.get_unverified_claims(token)
            kid = unverified_headers.get("kid")

            # Verify the issuer
            self.check_issuer(unverified_claims["iss"])
            decoded_key = await self.get_key(kid)

            token_decoded: Dict[str, Any] = jwt.decode(
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

    async def __call__(
        self, token: str = Depends(oauth2_scheme)
    ) -> Optional[Dict[str, Any]]:

        return await self.verify_access_token(token, auto_error=self.auto_error)
