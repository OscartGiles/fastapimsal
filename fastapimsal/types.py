from typing import Awaitable, Callable

import msal

LoadCacheCallable = Callable[[str], Awaitable[msal.SerializableTokenCache]]
SaveCacheCallable = Callable[[str, msal.SerializableTokenCache], Awaitable[None]]
RemoveCacheCallable = Callable[[str], Awaitable[None]]
