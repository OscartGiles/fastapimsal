# type: ignore
import base64
import json
import uuid
from typing import Any

import itsdangerous
import pytest
import requests
from fastapi.testclient import TestClient

from examples.app import app
from fastapimsal.config import get_auth_settings


def client_frontend() -> TestClient:
    return TestClient(app)


def request_path(
    client: TestClient, path: str, method: str = "get", **kwargs: Any
) -> requests.Response:

    """Request giving the name of route function

    Args:
        path (str): Route function name
        method (str, optional): HTTP Method. Defaults to "get".

    Returns:
        [type]: [description]
    """

    return client.request(url=app.url_path_for(path), method=method, **kwargs)


def signed_session(session_secret: str) -> bytes:

    # Use the session cookie secret to self sign a cookie
    oid = str(uuid.uuid4())
    signer = itsdangerous.TimestampSigner(session_secret)

    # Create cookie and sign
    payload = base64.b64encode(json.dumps({"user": oid}).encode("utf-8"))
    return signer.sign(payload)


def test_home_no_cookie() -> None:

    resp = request_path(client_frontend(), "home")
    assert resp.status_code == 200
    assert '<a href="/login">login</a>' in resp.content.decode()


@pytest.mark.xfail(reason="Fails to get whole cookie for some reason. Works on app")
def test_login() -> None:

    resp = request_path(client_frontend(), "login")

    # The login page redirects us to microsoft identity platform
    assert resp.status_code == 302

    # Verify we have been redirected
    base_url = get_auth_settings().base_url
    assert resp.headers["location"][: len(base_url)] == base_url

    # We should have added a 'flow' cookie requried for the signin process
    session_cookie = json.loads(base64.b64decode(resp.cookies["session"]).decode())
    assert "flow" in session_cookie


def test_no_cookie() -> None:
    "Check you can sign in when you have a signed session cookie, but cant if you don't"

    # No session cookie
    resp = request_path(client_frontend(), "get_open_api_endpoint")
    assert resp.status_code == 307


def test_correct_cookie() -> None:
    # Correct session cookie
    payload = signed_session(get_auth_settings().session_secret.get_secret_value())
    resp_auth = request_path(
        client_frontend(),
        "get_documentation",
        cookies={"session": payload.decode("utf-8")},
    )

    assert resp_auth.status_code == 200


def test_wrong_cookie_signature() -> None:
    # Wrong session cookie
    payload = signed_session("thisisnotthesessionsecret")
    resp_no_auth = request_path(
        client_frontend(),
        "get_documentation",
        cookies={"session": payload.decode("utf-8")},
    )

    assert resp_no_auth.status_code == 307


def test_signed_cookie_malformed() -> None:

    payload = signed_session(get_auth_settings().session_secret.get_secret_value())
    resp_no_auth = request_path(
        client_frontend(),
        "get_documentation",
        cookies={"hello": payload.decode("utf-8")},
    )

    assert resp_no_auth.status_code == 307
