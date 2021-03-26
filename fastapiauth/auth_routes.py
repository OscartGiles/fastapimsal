"""
Authentication with Azure Active Directory
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from .config import AuthSettings, logged_in

router = APIRouter()
auth_settings = AuthSettings()

# Register Azure AAD
oauth = OAuth()
oauth.register(
    name="azure",
    client_id=str(auth_settings.client_id),
    client_secret=auth_settings.client_secret.get_secret_value(),
    access_token_url=auth_settings.authority + "/oauth2/v2.0/token",
    access_token_params=None,
    authorize_url=auth_settings.authority + "/oauth2/v2.0/authorize",
    authorize_params=None,
    client_kwargs={"scope": "openid offline_access profile"},
    server_metadata_url=auth_settings.authority
    + "/v2.0/.well-known/openid-configuration",
)


@router.route("/login", include_in_schema=False)
async def login(request: Request):

    redirect_uri = request.url_for("authorized")

    if "http://0.0.0.0" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://0.0.0.0", "http://localhost")
    if "http://127.0.0.1" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://127.0.0.1", "http://localhost")

    return await oauth.azure.authorize_redirect(request, redirect_uri)


@router.get(
    "/getAToken",
    include_in_schema=False,
)  # Its absolute URL must match your app's redirect_uri set in AAD
async def authorized(request: Request):

    print(request.scope)
    token = await oauth.azure.authorize_access_token(request)
    user = await oauth.azure.parse_id_token(request, token)

    request.session["user"] = dict(user)

    return RedirectResponse(url=request.url_for("dash"))


@router.route("/logout", include_in_schema=False)
async def logout(request: Request, _=Depends(logged_in)):

    request.session.pop("user", None)
    # request.session.pop("tokens", None)
    return RedirectResponse(url=request.url_for("home"))


# # Define Authentication Routes
# def create_access_token(data: dict, expires_delta: timedelta):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + expires_delta
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(
#         to_encode,
#         auth_settings.access_token_secret.get_secret_value(),
#         algorithm=auth_settings.access_token_algorithm,
#     )
#     return encoded_jwt


# @router.get("/token", response_model=Token, include_in_schema=False)
# def token(user=Depends(logged_in)):

#     access_token_expires = timedelta(minutes=auth_settings.access_token_expire_minutes)

#     access_token = create_access_token(
#         data={"sub": user["preferred_username"], "roles": user["groups"]},
#         expires_delta=access_token_expires,
#     )
#     return {"access_token": access_token, "token_type": "bearer"}


# @router.get("/user", include_in_schema=False)
# async def user_home(request: Request, user=Depends(logged_in)):

#     return auth_templates.TemplateResponse(
#         "auth.html", {"request": request, "user": user}
#     )
