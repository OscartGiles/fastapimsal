from fastapi import FastAPI, Depends
from fastapi.responses import Response, HTMLResponse
import fastapiauth
from fastapiauth import logged_in

# Notice all docs are removed. We can add behind auth later
app = FastAPI(
    title="Example Auth",
    description="Example API with Oauth2 and docs behind auth",
    version="0.0.1",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Add session middleware
fastapiauth.init_auth(app)

# Add routes for logging in and generating access token
app.include_router(fastapiauth.auth_router, tags=["auth"])


@app.get("/", include_in_schema=False)
async def home():
    return HTMLResponse('<a href="/login">login</a>')


@app.get("/dash", include_in_schema=False)
async def dash(user=Depends(logged_in)):

    return HTMLResponse("<h1>You are signed in</h1>")