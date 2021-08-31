try:
    from importlib.metadata import version  # type: ignore

    __version__ = version("fastapimsal")
except ImportError:
    import pkg_resources

    __version__ = pkg_resources.get_distribution("fastapimsal").version


from . import types
from .auth_routes import f_logged_in
from .init_auth import init_auth
from .security import TokenVerifier

__all__ = ["init_auth", "f_logged_in", "types", "TokenVerifier"]
