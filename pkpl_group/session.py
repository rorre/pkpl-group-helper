import os
from itsdangerous import URLSafeSerializer
from robyn import Request, Response

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set")

s = URLSafeSerializer(SECRET_KEY)


def login_session(user_id: str, response: Response):
    token = s.dumps({"user_id": user_id})
    # what the fuck
    response.set_cookie(
        "Set-Cookie",
        f"session={token}; HttpOnly; SameSite=Strict",
    )
    return response


def get_user(request: Request) -> str | None:
    session_cookie = request.headers.get("cookie")
    if not session_cookie:
        return None

    cookies = session_cookie.split(";")
    for cookie in cookies:
        if cookie.startswith("session="):
            session_cookie = cookie.split("=")[1]
            break
    else:
        return None

    try:
        data = s.loads(session_cookie)
        return data.get("user_id")
    except Exception:
        return None
