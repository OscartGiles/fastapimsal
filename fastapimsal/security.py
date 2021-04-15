"""Validate JWT from Azure"""

from base64 import decode
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import httpx

from .config import get_auth_settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=True)


def check_issuer(issuer: str):
    if issuer != get_auth_settings().issuer:
        raise HTTPException(
            status_code=401, detail=f"Unrecognised issuer {issuer} in token"
        )
    return issuer


async def get_key_uri():

    token_meta_data_uri = f"https://login.microsoftonline.com/{get_auth_settings().tenant_id}/v2.0/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        res = await client.get(token_meta_data_uri)

    key_uri = res.json()["jwks_uri"]
    return key_uri


async def get_key(key_id: str):

    key_uri = await get_key_uri()
    async with httpx.AsyncClient() as client:
        res = await client.get(key_uri)

    all_keys = res.json()["keys"]
    decoded_key = next(filter(lambda x: x["kid"] == key_id, all_keys), None)

    if not decoded_key:
        raise HTTPException(status_code=401, detail="Unrecognised kid in token")
    return decoded_key


async def token_verified(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authorized. Token was invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )

    unverified_headers = jwt.get_unverified_header(token)
    unverified_claims = jwt.get_unverified_claims(token)
    kid = unverified_headers.get("kid")

    # Verify the issuer
    check_issuer(unverified_claims["iss"])
    decoded_key = await get_key(kid)

    try:
        token_decoded = jwt.decode(
            token,
            decoded_key,
            algorithms=unverified_headers["alg"],
            audience=str(get_auth_settings().client_id),
        )
    except:
        raise credentials_exception

    return token_decoded