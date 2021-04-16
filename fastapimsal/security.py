"""Validate JWT from Azure"""


from typing import Optional, Dict
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import httpx
from async_lru import alru_cache

from .config import get_auth_settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


def check_issuer(issuer: str):
    if issuer != get_auth_settings().issuer:
        raise HTTPException(
            status_code=401, detail=f"Unrecognised issuer {issuer} in token"
        )
    return issuer


@alru_cache()
async def get_key_uri():

    token_meta_data_uri = get_auth_settings().token_metadata_uri
    async with httpx.AsyncClient() as client:
        res = await client.get(token_meta_data_uri)

    key_uri = res.json()["jwks_uri"]
    return key_uri


@alru_cache()
async def get_key(key_id: str):

    key_uri = await get_key_uri()
    async with httpx.AsyncClient() as client:
        res = await client.get(key_uri)

    all_keys = res.json()["keys"]
    decoded_key = next(filter(lambda x: x["kid"] == key_id, all_keys), None)

    if not decoded_key:
        raise HTTPException(status_code=401, detail="Unrecognised kid in token")
    return decoded_key


# async def token_verified(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Not authorized. Token was invalid",
#         headers={"WWW-Authenticate": "Bearer"},
#     )

#     unverified_headers = jwt.get_unverified_header(token)
#     unverified_claims = jwt.get_unverified_claims(token)
#     kid = unverified_headers.get("kid")

#     # Verify the issuer
#     check_issuer(unverified_claims["iss"])
#     decoded_key = await get_key(kid)

#     try:
#         token_decoded = jwt.decode(
#             token,
#             decoded_key,
#             algorithms=unverified_headers["alg"],
#             audience=str(get_auth_settings().client_id),
#         )
#     except:
#         raise credentials_exception

#     return token_decoded


class TokenVerifier:
    def __init__(
        self,
        auto_error: bool = True,
    ):
        self.auto_error = auto_error

    async def __call__(self, token: str = Depends(oauth2_scheme)) -> Optional[Dict]:

        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized. Token was invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

        # If token has incorrect format
        if not token and self.auto_error:
            raise credentials_exception

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
            if self.auto_error:
                raise credentials_exception
            else:
                return None

        return token_decoded
