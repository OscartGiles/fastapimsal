from typing import Optional
import msal
from .config import get_auth_settings


def build_msal_app(
    cache: Optional[msal.SerializableTokenCache] = None, authority: str = None
) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        str(get_auth_settings().client_id),
        authority=authority or get_auth_settings().authority,
        client_credential=get_auth_settings().client_secret.get_secret_value(),
        token_cache=cache,
    )
