import os
import pathlib
from urllib.parse import urlparse
from robyn import Request, Response, Robyn
from robyn.templating import JinjaTemplate

from pkpl_group.alert import alert, get_alerts
from pkpl_group.cas import CASClient
from pkpl_group.db import Credential, fetch_group, fetch_group_by_npm, fetch_group_to_pentest, setup_database, write_log
from pkpl_group.session import get_user, login_session

app = Robyn(__file__)
setup_database()
SERVICE_URL = os.getenv("SERVICE_URL", "http://127.0.0.1:8080/auth")

current_file_path = pathlib.Path(__file__).parent.resolve()
template = JinjaTemplate(os.path.join(current_file_path, "templates"))

REDIRECT_HTML = """
<!DOCTYPE html>
<html>
<head><meta http-equiv="refresh" content="0; url='REDIRECT_URL'"></head>
<body></body>
</html>
"""


@app.get("/")
def index(request: Request):
    user = get_user(request)
    if not user:
        return Response(
            status_code=302,
            headers={"Location": "/auth"},
            description="",
        )

    group = fetch_group_by_npm(user)
    if not group:
        return Response(
            status_code=404,
            headers={},
            description=f"Your account is not in any group. If this is a mistake, please contact Ren. Your user: {user}",
        )

    return template.render_template(
        "index.html",
        alerts=get_alerts(user),
        group=group,
    )


@app.get("/me")
def me(request: Request):
    user = get_user(request)
    if not user:
        return Response(
            status_code=302,
            headers={"Location": "/auth"},
            description="",
        )

    group = fetch_group_by_npm(user)
    if not group:
        return Response(
            status_code=404,
            headers={},
            description="Group not found",
        )

    return template.render_template(
        "info.html",
        group=group,
        is_complete=len(group.credentials) > 0 or len(group.links) > 0,
        should_hide=False,
    )


@app.get("/pentest")
def pentest(request: Request):
    user = get_user(request)
    if not user:
        return Response(
            status_code=302,
            headers={"Location": "/auth"},
            description="",
        )

    group = fetch_group_by_npm(user)
    if not group:
        return Response(
            status_code=404,
            headers={},
            description="Group not found",
        )

    group_to_pentest = fetch_group_to_pentest(group.id)
    return template.render_template(
        "info.html",
        group=group_to_pentest,
        is_complete=len(group.credentials) > 0 or len(group.links) > 0,
        should_hide=True,
    )


@app.post("/")
def post_index(request: Request):
    user = get_user(request)
    if not user:
        return Response(
            status_code=302,
            headers={"Location": "/auth"},
            description="",
        )

    group = fetch_group_by_npm(user)
    if not group:
        return Response(
            status_code=404,
            headers={},
            description="Group not found",
        )

    data = request.form_data
    links: list[str] = []
    credentials: dict[str, Credential] = {}
    for key, value in data.items():
        if key.startswith("link-") and value.strip():
            links.append(value)
        elif key.startswith("username-"):
            index = key.split("-")[1]
            if index not in credentials:
                credentials[index] = Credential("", "", "")
            credentials[index].username = value
        elif key.startswith("password-"):
            index = key.split("-")[1]
            if index not in credentials:
                credentials[index] = Credential("", "", "")
            credentials[index].password = value
        elif key.startswith("notes-"):
            index = key.split("-")[1]
            if index not in credentials:
                credentials[index] = Credential("", "", "")
            credentials[index].notes = value

    is_valid = True
    for link in links:
        parsed = urlparse(link)
        if not parsed.netloc.endswith(".pkpl.cs.ui.ac.id"):
            is_valid = False
            break

    for cred in credentials.values():
        if len(cred.username) > 128:
            is_valid = False
            break
        if len(cred.password) > 128:
            is_valid = False
            break

    if is_valid:
        group.links = links
        group.credentials = [cred for cred in credentials.values() if cred.username or cred.password]
        group.additional = data.get("additional", "")
        group.save()
        write_log(user, group.id, "User updated their group information")
    else:
        alert(user, "Invalid input.")

    return Response(
        status_code=302,
        headers={"Location": "/"},
        description="",
    )


@app.get("/auth")
def auth(request: Request):
    cas = CASClient(SERVICE_URL)
    ticket = request.query_params.get("ticket")
    if not ticket:
        return Response(
            status_code=302,
            headers={"Location": cas.login_url},
            description="",
        )

    try:
        response = cas.authenticate(ticket)
        data = response.get("serviceResponse", {})
        if "authenticationSuccess" not in data:
            raise Exception("SSO failed")
    except Exception:
        return Response(
            status_code=401,
            headers={},
            description="Failed to authenticate",
        )

    user = data["authenticationSuccess"]
    if "npm" not in user["attributes"]:
        return Response(
            status_code=401,
            headers={},
            description="Failed to authenticate",
        )

    attributes = user["attributes"]

    response = Response(
        status_code=200,
        headers={"Content-Type": "text/html"},
        description=REDIRECT_HTML,
    )
    response = login_session(attributes["npm"], response)
    return response
