# FastAPI Auth

**This is a WIP and should not be used in production**

Authenticate users with FastAPI using the [Microsoft MSAL Library](https://msal-python.readthedocs.io/en/latest/) and Azure Active Directory.

## Getting started

See [examples/app.py](examples/app.py) for a simple example.

Create a `.auth.env` file:

```bash
echo "session_expire_time_minutes=1
session_secret=<Session-Cookie-Secret>
client_id=<Application-client-id>
client_secret=<Application-Client-secret>
tenant_id=<Tenant-id" > .env
```

For the `session_secret` its a good idea to create a secret with `openssl rand -hex 32`
