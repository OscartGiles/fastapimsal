try:
    from importlib.metadata import version

    __version__ = version("fastapimsal")
except ImportError:
    import pkg_resources

    __version__ = pkg_resources.get_distribution("fastapimsal").version

from . import backend, frontend
from .init_auth import init_auth
from .types import RequiresLoginException, UserIdentity, UserIdentityToken

__all__ = [
    "init_auth",
    "UserIdentity",
    "UserIdentityToken",
    "frontend",
    "backend",
    "RequiresLoginException",
]
