"""
Authentication for Odysseus access levels
"""

# pylint: disable=C0103

from enum import Enum, unique
from typing import List
from uuid import UUID

# from fastapi import Depends, HTTPException, status, Security, Request
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, SecurityScopes
# from jose import JWTError, jwt, ExpiredSignatureError
# from pydantic import BaseModel, ValidationError

# from .config import AuthTokenSettings, logged_in


# @unique
# class Roles(Enum):

#     basic = UUID("2bdb89cb-7049-408a-a666-b1a176ad9b04")
#     enhanced = UUID("4452e7b5-332a-460d-884a-02d8936b0476")
#     admin = UUID("fa40b0d6-1c15-48cb-b2d4-4c6cff72502d")


# class TokenData(BaseModel):
#     username: str
#     roles: List[UUID]


# auth_settings = AuthTokenSettings()
# bearer_scheme = HTTPBearer()


# async def get_bearer_user(
#     security_roles: SecurityScopes,
#     credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
# ) -> TokenData:
#     """
#     Gets a user's access permissions (in the form of group membership)
#     using their token
#     """

#     token = credentials.credentials

#     if security_roles.scopes:
#         authenticate_value = f'Bearer roles="{security_roles.scope_str}"'
#     else:
#         authenticate_value = f"Bearer"

#     credentials_exception = HTTPException(
#         status_code=status.HTTP_403_FORBIDDEN,
#         detail="Authentication Error: Could not validate credentials",
#         headers={"WWW-Authenticate": authenticate_value},
#     )

#     credentials_timeout_exception = HTTPException(
#         status_code=status.HTTP_403_FORBIDDEN,
#         detail="Authentication Error: Credentials have expired",
#         headers={"WWW-Authenticate": authenticate_value},
#     )

#     # Validate the token and get payload
#     try:
#         payload = jwt.decode(
#             token,
#             auth_settings.access_token_secret.get_secret_value(),
#             algorithms=[auth_settings.access_token_algorithm],
#         )
#         username: str = payload.get("sub")
#         roles = payload.get("roles", [])

#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username, roles=roles)

#     except (JWTError, ValidationError) as error:
#         if isinstance(error, ExpiredSignatureError):
#             raise credentials_timeout_exception
#         raise credentials_exception

#     # Check user has required roles
#     for role in security_roles.scopes:
#         role_uuid = UUID(role)
#         if role_uuid in token_data.roles:
#             return token_data

#     raise HTTPException(
#         status_code=status.HTTP_403_FORBIDDEN,
#         detail="Not enough permissions to access this resource",
#         headers={"WWW-Authenticate": authenticate_value},
#     )


# async def oauth_basic_user(
#     user: TokenData = Security(
#         get_bearer_user,
#         scopes=[Roles.admin.value.hex, Roles.enhanced.value.hex, Roles.basic.value.hex],
#     )
# ) -> TokenData:
#     """
#     Allows Basic user access to routes
#     """
#     return user


# async def oauth_enhanced_user(
#     user: TokenData = Security(
#         get_bearer_user, scopes=[Roles.admin.value.hex, Roles.enhanced.value.hex]
#     )
# ) -> TokenData:
#     """
#     Allows Enhanced user access to routes
#     """
#     return user


# async def oauth_admin_user(
#     user: TokenData = Security(get_bearer_user, scopes=[Roles.admin.value.hex])
# ) -> TokenData:
#     """
#     Allows Admin user access to routes
#     """
#     return user
