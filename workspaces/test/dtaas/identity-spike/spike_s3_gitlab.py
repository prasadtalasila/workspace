"""Spike S3: GitLab OAuth behaviour for login-relay and workspace backups.

Runs on the ``users`` network next to a throwaway GitLab served under
``/gitlab`` (browsers ``GITLAB_URL``, containers ``GITLAB_INTERNAL_URL``)
and the test compose's Oathkeeper. Registers the ``dtaas-login`` and
``workspace-backup`` applications of ``docs/design/storage/STORAGE_GITLAB.md``,
drives the browser steps over HTTP, and checks PKCE, redirect URIs,
scopes, token lifetimes, refresh, revocation, the token-info and userinfo
answers, and what Oathkeeper passes on from login-relay's introspection
answer. Prints one line per check; GitLab's answers, redacted, go to
``/spike-out/recorded`` for login-relay's contract tests.

Usage: ``python spike_s3_gitlab.py``.
"""

# jwt and requests are installed only in the spike image.
# pylint: disable=import-error

from __future__ import annotations

import base64
import html
import http.server
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlencode

import jwt
import requests

from spike_common import (TIMEOUT, find_form, finish, forms, jwt_claims,
                          jwt_header, oauth_error, pkce_pair, query, record,
                          save)

PUBLIC = os.environ.get("GITLAB_URL", "http://gitlab.test/gitlab")
INTERNAL = os.environ.get("GITLAB_INTERNAL_URL", "http://gitlab/gitlab")
ADMIN_TOKEN = os.environ["SPIKE_ADMIN_TOKEN"]
PASSWORD = os.environ["SPIKE_USER_PASSWORD"]
OATHKEEPER = os.environ.get("OATHKEEPER_URL", "http://oathkeeper:4456")
DTAAS = "http://dtaas.test"
LOGIN_REDIRECT = f"{DTAAS}/login-relay/callback"
BACKUP_REDIRECT = f"{DTAAS}/login-relay/oauth/gitlab/callback"
WORKSPACE_USERS = {"user1", "user2"}

APPS: dict[str, dict[str, Any]] = {}


# --- GitLab admin API -------------------------------------------------------


def api(method: str, path: str, **kwargs: Any) -> requests.Response:
    """Call the GitLab REST API as the spike's admin."""
    return requests.request(method, f"{INTERNAL}/api/v4{path}",
                            headers={"PRIVATE-TOKEN": ADMIN_TOKEN},
                            timeout=TIMEOUT, **kwargs)


def wait_for_api() -> None:
    """Wait until the seeded admin token works."""
    for _ in range(60):
        try:
            if api("GET", "/user").status_code == 200:
                return
        except requests.ConnectionError:
            pass
        time.sleep(5)
    raise SystemExit("GitLab API not ready; did gitlab_bootstrap.rb run?")


def register_apps() -> None:
    """Create the two applications of STORAGE_GITLAB afresh."""
    for app in api("GET", "/applications").json():
        if app["application_name"] in ("dtaas-login", "workspace-backup"):
            api("DELETE", f"/applications/{app['id']}")
    for name, scopes, redirect, confidential in (
            ("dtaas-login", "openid", LOGIN_REDIRECT, True),
            ("workspace-backup", "openid write_repository", BACKUP_REDIRECT,
             False)):
        answer = api("POST", "/applications", data={
            "name": name, "redirect_uri": redirect, "scopes": scopes,
            "confidential": str(confidential).lower()})
        answer.raise_for_status()
        APPS[name] = answer.json() | {"redirect": redirect, "scopes": scopes}
        save(f"admin-create-application-{name}", answer)
    record("non-confidential application registered",
           APPS["workspace-backup"].get("confidential") is False,
           f"confidential={APPS['workspace-backup'].get('confidential')}, "
           f"secret returned={bool(APPS['workspace-backup'].get('secret'))}")


def user_id(name: str) -> int:
    """Return the GitLab id of ``name``."""
    return api("GET", "/users", params={"username": name}).json()[0]["id"]


def ensure_project(owner: str, name: str) -> None:
    """Create a private project with a README for ``owner`` if missing."""
    if api("GET", f"/projects/{owner}%2F{name}").status_code == 200:
        return
    api("POST", f"/projects/user/{user_id(owner)}", data={
        "name": name, "visibility": "private",
        "initialize_with_readme": "true"}).raise_for_status()


# --- Browser steps over HTTP ------------------------------------------------


class Browser:
    """A signed-in GitLab web session, as the user's browser holds it."""

    def __init__(self, user: str) -> None:
        self.user = user
        self.session = requests.Session()
        page = self.session.get(f"{PUBLIC}/users/sign_in", timeout=TIMEOUT)
        form = find_form(page, r"/users/sign_in$")
        form["fields"].update({"user[login]": user,
                               "user[password]": PASSWORD})
        done = self.session.post(form["action"], data=form["fields"],
                                 timeout=TIMEOUT)
        if "/users/sign_in" in done.url:
            raise SystemExit(f"sign-in of {user} failed at {done.url}")

    def authorize(self, params: dict[str, str]) -> requests.Response:
        """Open the authorize URL; return GitLab's page or redirect."""
        return self.session.get(f"{PUBLIC}/oauth/authorize?"
                                f"{urlencode(params)}",
                                allow_redirects=False, timeout=TIMEOUT)

    def approve(self, page: requests.Response) -> requests.Response:
        """Press "Authorize" on GitLab's consent page."""
        form = find_form(page, r"/oauth/authorize$")
        if form["fields"].get("_method") == "delete":
            raise LookupError("first form is the deny form")
        return self.session.post(form["action"], data=form["fields"],
                                 allow_redirects=False, timeout=TIMEOUT)

    def deny(self, page: requests.Response) -> requests.Response:
        """Press "Deny" on GitLab's consent page."""
        for form in forms(page):
            if form["fields"].get("_method") == "delete":
                return self.session.post(form["action"], data=form["fields"],
                                         allow_redirects=False,
                                         timeout=TIMEOUT)
        raise LookupError("no deny form")


def auth_params(  # pylint: disable=too-many-arguments
        app: str, challenge: str | None, *, method: str = "S256",
        scope: str | None = None, redirect: str | None = None,
        state: str | None = None,
        nonce: str | None = None) -> dict[str, str]:
    """Build the authorize parameters of STORAGE_GITLAB step 4."""
    params = {"client_id": APPS[app]["application_id"],
              "redirect_uri": redirect or APPS[app]["redirect"],
              "response_type": "code",
              "scope": scope or APPS[app]["scopes"],
              "state": state or f"user1.{secrets.token_urlsafe(32)}"}
    if nonce:
        params["nonce"] = nonce
    if challenge is not None:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = method
    return params


def is_error_page(page: requests.Response) -> bool:
    """Whether GitLab answered with its OAuth error page."""
    return page.status_code == 200 and "An error has occurred" in page.text \
        and not forms(page)


def redirect_target(page: requests.Response) -> str:
    """Where GitLab sends the browser: a 302, or its "Redirecting" page."""
    if page.is_redirect:
        return page.headers.get("Location", "")
    if page.status_code == 200 and "Redirecting" in page.text:
        found = re.search(r'href="([^"]+)"', page.text.split("Redirecting",
                                                             1)[1])
        return html.unescape(found.group(1)) if found else ""
    return ""


def get_code(browser: Browser, params: dict[str, str]) -> tuple[str, bool]:
    """Run the authorize step to its redirect; return code, consent shown."""
    page = browser.authorize(params)
    consent = page.status_code == 200 and bool(forms(page))
    if consent:
        page = browser.approve(page)
    location = redirect_target(page)
    if not location.startswith(params["redirect_uri"]):
        raise RuntimeError(f"no redirect to the callback: HTTP "
                           f"{page.status_code} {location[:120]}")
    got = query(location)
    if got.get("state") != params["state"]:
        raise RuntimeError("state not returned unchanged")
    return got["code"], consent


def token(data: dict[str, str]) -> requests.Response:
    """POST to the token endpoint at the internal address."""
    return requests.post(f"{INTERNAL}/oauth/token", data=data,
                         timeout=TIMEOUT)


def redeem(app: str, code: str, verifier: str | None,
           redirect: str | None = None,
           secret: bool = False) -> requests.Response:
    """Redeem a code as workspace-admin (public) or login-relay does."""
    data = {"grant_type": "authorization_code", "code": code,
            "client_id": APPS[app]["application_id"],
            "redirect_uri": redirect or APPS[app]["redirect"]}
    if verifier is not None:
        data["code_verifier"] = verifier
    if secret:
        data["client_secret"] = APPS[app]["secret"]
    return token(data)


def connect(browser: Browser, app: str = "workspace-backup",
            nonce: str | None = None) -> dict[str, Any]:
    """Complete a PKCE login for ``app``; return GitLab's token answer."""
    verifier, challenge = pkce_pair()
    code, _ = get_code(browser, auth_params(
        app, challenge, state=f"{browser.user}.{secrets.token_urlsafe(32)}",
        nonce=nonce))
    answer = redeem(app, code, verifier,
                    secret=APPS[app]["confidential"])
    answer.raise_for_status()
    return answer.json()


def bearer(access: str) -> dict[str, str]:
    """Authorization header for an access token."""
    return {"Authorization": f"Bearer {access}"}


def token_info(access: str) -> requests.Response:
    """GitLab's token information answer for ``access``."""
    return requests.get(f"{INTERNAL}/oauth/token/info",
                        headers=bearer(access), timeout=TIMEOUT)


def userinfo(access: str) -> requests.Response:
    """GitLab's OpenID userinfo answer for ``access``."""
    return requests.get(f"{INTERNAL}/oauth/userinfo", headers=bearer(access),
                        timeout=TIMEOUT)


# --- Checks -----------------------------------------------------------------


def check_discovery() -> dict[str, Any]:
    """Discovery at the internal address names the public issuer."""
    answer = requests.get(f"{INTERNAL}/.well-known/openid-configuration",
                          timeout=TIMEOUT)
    save("discovery", answer)
    doc = answer.json()
    record("discovery issuer is GITLAB_URL", doc.get("issuer") == PUBLIC,
           f"issuer {doc.get('issuer')}")
    record("discovery advertises introspection_endpoint (design: none)",
           "introspection_endpoint" in doc,
           str(doc.get("introspection_endpoint")))
    record("PKCE methods advertised",
           "S256" in doc.get("code_challenge_methods_supported", []),
           f"{doc.get('code_challenge_methods_supported')}")
    record("write_repository is an advertised scope",
           "write_repository" in doc.get("scopes_supported", []),
           f"{len(doc.get('scopes_supported', []))} scopes")
    record("device authorization endpoint (informational)", True,
           str(doc.get("device_authorization_endpoint")))
    keys = requests.get(f"{INTERNAL}/oauth/discovery/keys", timeout=TIMEOUT)
    save("discovery-keys", keys)
    algs = [k.get("alg") for k in keys.json().get("keys", [])]
    record("keys at GITLAB_INTERNAL_URL/oauth/discovery/keys",
           keys.status_code == 200 and bool(algs), f"algs {algs}")
    return doc


def check_login_client(browser: Browser) -> dict[str, Any]:
    """dtaas-login: confidential, openid, ID token valid per LR-3."""
    verifier, challenge = pkce_pair()
    nonce = secrets.token_urlsafe(16)
    params = auth_params("dtaas-login", challenge, nonce=nonce,
                         state=secrets.token_urlsafe(16))
    code, consent = get_code(browser, params)
    record("consent page on first authorization (dtaas-login)", consent)
    no_secret = redeem("dtaas-login", code, verifier)
    record("confidential application refuses redeem without secret",
           no_secret.status_code in (400, 401), oauth_error(no_secret))
    save("token-confidential-without-secret", no_secret)
    code, consent = get_code(browser, params | {
        "state": secrets.token_urlsafe(16)})
    record("consent again while no token was issued", consent)
    answer = redeem("dtaas-login", code, verifier, secret=True)
    save("token-dtaas-login", answer)
    grant = answer.json()
    page = browser.authorize(params | {"state": secrets.token_urlsafe(16)})
    record("no consent once a token exists: 200 Redirecting page",
           page.status_code == 200 and not forms(page)
           and redirect_target(page).startswith(LOGIN_REDIRECT),
           f"HTTP {page.status_code}, Location header "
           f"{page.headers.get('Location')}")
    record("dtaas-login token: openid only",
           grant.get("scope") == "openid", f"scope {grant.get('scope')}")
    record("access token lives 2 hours", grant.get("expires_in") == 7200,
           f"expires_in {grant.get('expires_in')}")
    check_id_token(grant.get("id_token", ""), "dtaas-login", nonce)
    return grant


def check_id_token(id_token: str, app: str, nonce: str) -> None:
    """Signature from the internal keys; iss, aud, nonce, lifetime."""
    if not id_token:
        record(f"ID token in code answer ({app})", False, "missing")
        return
    claims = jwt_claims(id_token)
    save(f"id-token-claims-{app}", claims, header=jwt_header(id_token))
    keys = jwt.PyJWKClient(f"{INTERNAL}/oauth/discovery/keys")
    try:
        jwt.decode(id_token, keys.get_signing_key_from_jwt(id_token).key,
                   algorithms=["RS256"], audience=APPS[app]["application_id"],
                   issuer=PUBLIC)
        record(f"ID token verifies: keys, iss GITLAB_URL, aud ({app})", True,
               f"alg {jwt_header(id_token).get('alg')}")
    except jwt.PyJWTError as exc:
        record(f"ID token verifies: keys, iss GITLAB_URL, aud ({app})", False,
               repr(exc))
    record(f"ID token echoes nonce ({app})", claims.get("nonce") == nonce)
    record(f"ID token lifetime (informational, {app})", True,
           f"exp-iat {claims['exp'] - claims['iat']}s, "
           f"claims {sorted(claims)}")


def check_pkce(browser: Browser) -> None:
    """workspace-backup is public: PKCE without secret, and only with it."""
    verifier, challenge = pkce_pair()
    params = auth_params("workspace-backup", challenge)
    code, consent = get_code(browser, params)
    record("consent page on first authorization (workspace-backup)", consent)
    answer = redeem("workspace-backup", code, None)
    record("public redeem without code_verifier refused",
           answer.status_code == 400, oauth_error(answer))
    save("token-pkce-missing-verifier", answer)
    code, _ = get_code(browser, params | {"state": f"user1.{'w' * 43}"})
    answer = redeem("workspace-backup", code, pkce_pair()[0])
    record("public redeem with wrong code_verifier refused",
           answer.status_code == 400, oauth_error(answer))
    save("token-pkce-wrong-verifier", answer)
    code, _ = get_code(browser, params | {"state": f"user1.{'r' * 43}"})
    answer = redeem("workspace-backup", code, verifier)
    record("public redeem with verifier and no secret",
           answer.status_code == 200, oauth_error(answer))
    again = redeem("workspace-backup", code, verifier)
    record("code is single use", again.status_code == 400,
           oauth_error(again))
    save("token-code-reused", again)

    try:
        code, _ = get_code(browser, auth_params("workspace-backup", None))
        answer = redeem("workspace-backup", code, None)
        record("public application without code_challenge: no PKCE",
               True, f"informational: authorize gives a code, redeem "
                     f"without verifier {oauth_error(answer)}")
    except RuntimeError as exc:
        record("public application without code_challenge: no PKCE", True,
               f"informational: refused at authorize: {exc}")
    plain = pkce_pair()[0]
    try:
        code, _ = get_code(browser, auth_params(
            "workspace-backup", plain, method="plain"))
        answer = redeem("workspace-backup", code, plain)
        record("code_challenge_method=plain (informational)", True,
               f"redeem {oauth_error(answer)}")
    except RuntimeError as exc:
        record("code_challenge_method=plain (informational)", True,
               f"refused at authorize: {exc}")


def check_redirect_uris(browser: Browser) -> None:
    """Only the exact registered address is accepted."""
    for variant in (BACKUP_REDIRECT + "/x", BACKUP_REDIRECT + "?next=/x",
                    BACKUP_REDIRECT + "/", "http://evil.test/login-relay/"
                    "oauth/gitlab/callback",
                    BACKUP_REDIRECT.replace("http:", "https:"),
                    BACKUP_REDIRECT.upper()):
        page = browser.authorize(auth_params("workspace-backup",
                                             pkce_pair()[1],
                                             redirect=variant))
        if forms(page):
            page = browser.approve(page)
        target = redirect_target(page)
        label = variant[len('http://'):][:60]
        if "?" in variant:
            record(f"extra query on the registered URI accepted: {label}",
                   True, f"informational: code sent to "
                         f"{target.split('&code=')[0].split('?code=')[0]}")
            continue
        record(f"redirect_uri refused: {label}",
               is_error_page(page) and not target.startswith(variant),
               f"HTTP {page.status_code} error page")
    verifier, challenge = pkce_pair()
    code, _ = get_code(browser, auth_params("workspace-backup", challenge))
    answer = redeem("workspace-backup", code, verifier,
                    redirect=BACKUP_REDIRECT + "/x")
    record("redeem with other redirect_uri than authorize refused",
           answer.status_code == 400, oauth_error(answer))
    save("token-redirect-mismatch", answer)


def check_scopes(browser: Browser) -> None:
    """Scopes beyond the registration are refused."""
    page = browser.authorize(auth_params("workspace-backup", pkce_pair()[1],
                                         scope="openid api"))
    record("unregistered scope refused", is_error_page(page)
           and "scope is invalid" in page.text,
           f"HTTP {page.status_code} error page")


def check_token_answers(login: dict[str, Any],
                        backup: dict[str, Any]) -> None:
    """Fields of /oauth/token/info and /oauth/userinfo for both clients."""
    for app, grant in (("dtaas-login", login), ("workspace-backup", backup)):
        info = token_info(grant["access_token"])
        save(f"token-info-{app}", info)
        body = info.json()
        record(f"token/info fields ({app})", info.status_code == 200,
               f"{sorted(body)}")
        record(f"token/info application uid matches ({app})",
               (body.get("application") or {}).get("uid")
               == APPS[app]["application_id"],
               f"application {body.get('application')}")
        record(f"token/info expires_in near 7200 ({app})",
               7100 <= (body.get("expires_in") or 0) <= 7200,
               f"expires_in {body.get('expires_in')}, "
               f"scope {body.get('scope')}")
        info_user = userinfo(grant["access_token"])
        save(f"userinfo-{app}", info_user)
        body = info_user.json()
        record(f"userinfo nickname is the username ({app})",
               body.get("nickname") == "user1",
               f"fields {sorted(body)}")
        record(f"userinfo sub is token/info resource_owner_id ({app})",
               str(body.get("sub"))
               == str(token_info(grant["access_token"])
                      .json().get("resource_owner_id")),
               f"sub {body.get('sub')}")
    query_param = requests.get(f"{INTERNAL}/oauth/token/info",
                               params={"access_token":
                                       login["access_token"]},
                               timeout=TIMEOUT)
    record("token/info also takes ?access_token= (informational)", True,
           f"HTTP {query_param.status_code}")
    bad = token_info("not-a-token")
    save("token-info-unknown-token", bad)
    record("token/info for an unknown token is 401",
           bad.status_code == 401, f"HTTP {bad.status_code} {bad.text[:80]}")
    bad = userinfo("not-a-token")
    save("userinfo-unknown-token", bad)
    record("userinfo for an unknown token is 401",
           bad.status_code == 401, f"HTTP {bad.status_code}")


def refresh(app: str, refresh_token: str,
            secret: bool = False) -> requests.Response:
    """Refresh a grant as workspace-admin (public) does."""
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token,
            "client_id": APPS[app]["application_id"]}
    if secret:
        data["client_secret"] = APPS[app]["secret"]
    return token(data)


def check_refresh(backup: dict[str, Any]) -> dict[str, Any]:
    """Refresh rotates the refresh token and returns no ID token."""
    answer = refresh("workspace-backup", backup["refresh_token"])
    save("token-refresh-workspace-backup", answer)
    new = answer.json()
    record("public refresh without secret", answer.status_code == 200,
           oauth_error(answer) if answer.status_code != 200 else "")
    record("refresh rotates the refresh token",
           new.get("refresh_token") not in (None, backup["refresh_token"]))
    record("ID token on refresh (informational)", True,
           f"fields {sorted(new)}")
    if "id_token" in new:
        claims = jwt_claims(new["id_token"])
        save("id-token-claims-refresh", claims,
             header=jwt_header(new["id_token"]))
        record("refresh ID token: fresh iat, 2 minutes, no nonce", True,
               f"informational: iat-auth_time "
               f"{claims['iat'] - claims.get('auth_time', 0)}s, exp-iat "
               f"{claims['exp'] - claims['iat']}s, nonce "
               f"{'nonce' in claims}, aud is the app "
               f"{claims.get('aud') == APPS['workspace-backup']['application_id']}")
    record("refreshed access token lives 2 hours",
           new.get("expires_in") == 7200,
           f"expires_in {new.get('expires_in')}, scope {new.get('scope')}")
    old_access = token_info(backup["access_token"])
    record("old access token after refresh (informational)", True,
           f"token/info HTTP {old_access.status_code}")
    reuse = refresh("workspace-backup", backup["refresh_token"])
    save("token-refresh-reused", reuse)
    record("used refresh token refused", reuse.status_code == 400,
           oauth_error(reuse))
    after_reuse = token_info(new["access_token"])
    record("newest grant after a reuse attempt (informational)", True,
           f"token/info HTTP {after_reuse.status_code}")
    if after_reuse.status_code != 200:
        return {}
    login_refresh = refresh("dtaas-login", new["refresh_token"])
    record("refresh token bound to its application",
           login_refresh.status_code in (400, 401),
           oauth_error(login_refresh))
    return new


def basic(access: str) -> str:
    """The git ``http.extraHeader`` value admin.git.auth would build."""
    raw = base64.b64encode(f"oauth2:{access}".encode()).decode()
    return f"Authorization: Basic {raw}"


def git(access: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git with the token as admin.git.auth passes it."""
    return subprocess.run(
        ["git", "-c", f"http.extraHeader={basic(access)}",
         "-c", "credential.helper=", *args],
        capture_output=True, text=True, timeout=120, check=False,
        env=os.environ | {"GIT_TERMINAL_PROMPT": "0"})


def check_introspection_endpoint(login: dict[str, Any],
                                 backup: dict[str, Any]) -> None:
    """GitLab 19 advertises introspection: who may call it, what it says."""
    url = f"{INTERNAL}/oauth/introspect"
    login_app = APPS["dtaas-login"]
    cases = {
        "own token, client credentials": (
            login["access_token"], (login_app["application_id"],
                                    login_app["secret"]), {}),
        "workspace-backup token, dtaas-login credentials": (
            backup["access_token"], (login_app["application_id"],
                                     login_app["secret"]), {}),
        "token as its own bearer": (
            login["access_token"], None, bearer(login["access_token"])),
        "no client authentication": (login["access_token"], None, {}),
        "public client_id only": (
            backup["access_token"], None, {}),
    }
    for label, (value, auth, headers) in cases.items():
        data = {"token": value}
        if label == "public client_id only":
            data["client_id"] = APPS["workspace-backup"]["application_id"]
        answer = requests.post(url, data=data, auth=auth, headers=headers,
                               timeout=TIMEOUT)
        name = "introspect-" + re.sub(r"[^a-z]+", "-", label.lower())
        save(name.strip("-"), answer)
        try:
            body = answer.json()
        except ValueError:
            body = {}
        record(f"introspect, {label} (informational)", True,
               f"HTTP {answer.status_code} active {body.get('active')} "
               f"fields {sorted(body) if isinstance(body, dict) else body}")


def check_git(login: dict[str, Any], backup: dict[str, Any]) -> None:
    """write_repository pushes; the openid login token cannot."""
    ensure_project("user1", "thesis")
    ensure_project("user2", "private2")
    remote = f"{INTERNAL}/user1/thesis.git"
    work = f"/tmp/thesis-{secrets.token_hex(4)}"
    clone = git(backup["access_token"], "clone", "-q", remote, work)
    record("git clone with workspace-backup token over GITLAB_INTERNAL_URL",
           clone.returncode == 0, clone.stderr.strip()[-120:])
    if clone.returncode != 0:
        return
    with open(f"{work}/backup.txt", "w", encoding="utf-8") as handle:
        handle.write(f"spike {time.time()}\n")
    for args in (["add", "backup.txt"],
                 ["-c", "user.email=s@x", "-c", "user.name=s", "commit",
                  "-q", "-m", "spike"]):
        subprocess.run(["git", "-C", work, *args], check=True,
                       capture_output=True)
    push = git(backup["access_token"], "-C", work, "push", "-q")
    record("git push with openid write_repository", push.returncode == 0,
           push.stderr.strip()[-120:])
    push = git(login["access_token"], "-C", work, "push", "-q")
    ls_remote = git(login["access_token"], "ls-remote", remote)
    record("openid-only login token cannot read or push",
           push.returncode != 0 and ls_remote.returncode != 0,
           f"push: {push.stderr.strip()[-60:]}")
    other = git(backup["access_token"], "ls-remote",
                f"{INTERNAL}/user2/private2.git")
    record("user1's token cannot reach user2's private project",
           other.returncode != 0, other.stderr.strip()[-80:])


def revoke(app: str, value: str) -> requests.Response:
    """Revoke as workspace-admin's Disconnect does: token and client_id."""
    return requests.post(f"{INTERNAL}/oauth/revoke",
                         data={"token": value,
                               "client_id": APPS[app]["application_id"]},
                         timeout=TIMEOUT)


def check_revoke(browser: Browser) -> None:
    """A public client revokes without a secret; the grant ends."""
    grant = connect(browser)
    answer = revoke("workspace-backup", grant["refresh_token"])
    save("revoke-public-refresh-token", answer)
    record("public revoke with token and client_id",
           answer.status_code == 200, f"HTTP {answer.status_code}")
    again = refresh("workspace-backup", grant["refresh_token"])
    record("revoked refresh token refused", again.status_code == 400,
           oauth_error(again))
    record("access token of a revoked refresh token (informational)", True,
           f"token/info HTTP {token_info(grant['access_token']).status_code}")

    grant = connect(browser)
    answer = revoke("workspace-backup", grant["access_token"])
    record("revoking the access token ends it",
           answer.status_code == 200
           and token_info(grant["access_token"]).status_code == 401)
    record("refresh after access-token revoke (informational)", True,
           oauth_error(refresh("workspace-backup", grant["refresh_token"])))

    grant = connect(browser, "dtaas-login")
    answer = requests.post(f"{INTERNAL}/oauth/revoke",
                           data={"token": grant["access_token"],
                                 "client_id":
                                 APPS["dtaas-login"]["application_id"]},
                           timeout=TIMEOUT)
    record("confidential revoke with client_id only (informational)", True,
           f"HTTP {answer.status_code}, token/info now "
           f"{token_info(grant['access_token']).status_code}")


def check_blocked_user() -> None:
    """Blocking a user ends their grant (STORAGE_GITLAB, what stops)."""
    browser = Browser("user2")
    grant = connect(browser)
    uid = user_id("user2")
    api("POST", f"/users/{uid}/block").raise_for_status()
    try:
        answer = refresh("workspace-backup", grant["refresh_token"])
        save("token-refresh-blocked-user", answer)
        record("blocked user's refresh refused", answer.status_code != 200,
               oauth_error(answer))
        again = refresh("workspace-backup", grant["refresh_token"])
        record("blocked user's second refresh (informational)", True,
               oauth_error(again))
        record("blocked user's access token rejected by token/info",
               token_info(grant["access_token"]).status_code != 200)
    finally:
        api("POST", f"/users/{uid}/unblock")
    again = refresh("workspace-backup", grant["refresh_token"])
    record("grant after unblocking (informational)", True,
           f"refresh {oauth_error(again)}")


def check_consent_denied() -> None:
    """Deny on the consent page returns error=access_denied."""
    fresh = Browser("user2")
    params = auth_params("workspace-backup", pkce_pair()[1],
                         state=f"user2.{secrets.token_urlsafe(32)}")
    page = fresh.authorize(params)
    if page.status_code != 200:
        record("deny on consent returns access_denied", False,
               f"no consent page: HTTP {page.status_code}")
        return
    answer = fresh.deny(page)
    got = query(answer.headers.get("Location", ""))
    record("deny on consent returns access_denied",
           got.get("error") == "access_denied"
           and got.get("state") == params["state"],
           f"HTTP {answer.status_code} {got.get('error')}")


# --- Fake login-relay for the Oathkeeper check -------------------------------

SEEN: list[dict[str, Any]] = []


def introspect(value: str) -> dict[str, Any]:
    """LOGIN_RELAY's GitLab adapter: token/info and userinfo to RFC 7662."""
    info = token_info(value)
    if info.status_code != 200:
        return {"active": False}
    body = info.json()
    if (body.get("application") or {}).get("uid") != \
            APPS["dtaas-login"]["application_id"]:
        return {"active": False}
    user = userinfo(value).json()
    if user.get("nickname") not in WORKSPACE_USERS:
        return {"active": False}
    return {"active": True, "username": user["nickname"],
            "sub": str(body["resource_owner_id"]),
            "client_id": body["application"]["uid"],
            "scope": " ".join(body.get("scope") or []),
            "exp": int(time.time()) + int(body["expires_in"]),
            "token_type": "Bearer", "ext": {"groups": ["dtaas"]}}


class Relay(http.server.BaseHTTPRequestHandler):
    """Answers Oathkeeper's introspection and authorization calls."""

    def do_POST(self) -> None:  # pylint: disable=invalid-name
        """Serve /token/introspect and /authz/workspace/<user>."""
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/token/introspect":
            form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            self.reply(200, introspect(form.get("token", "")))
        elif self.path.startswith("/authz/workspace/"):
            payload = json.loads(raw or b"{}")
            SEEN.append(payload)
            owner = self.path.rsplit("/", 1)[1]
            extra = payload.get("subject", {}).get("extra", {})
            self.reply(200 if extra.get("username") == owner else 403, {})
        else:
            self.reply(404, {})

    def reply(self, status: int, body: dict[str, Any]) -> None:
        """Send a JSON answer."""
        data = json.dumps(body).encode()
        self.send_response(status)
        for header, value in (("Content-Type", "application/json"),
                              ("Content-Length", str(len(data)))):
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:  # pylint: disable=arguments-differ
        """Stay quiet: the checks print their own lines."""


def decision(path: str, cookie: str) -> requests.Response:
    """Ask Oathkeeper's decision API as Traefik's forwardAuth does."""
    return requests.get(f"{OATHKEEPER}/decisions{path}",
                        headers={"X-Forwarded-Proto": "http",
                                 "X-Forwarded-Host": "dtaas.test",
                                 "X-Forwarded-Uri": path,
                                 "Cookie": f"dtaas_access_token={cookie}"},
                        allow_redirects=False, timeout=TIMEOUT)


def check_oathkeeper(login: dict[str, Any], backup: dict[str, Any]) -> None:
    """Which introspection fields reach .Extra and the header mutator."""
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Relay)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for _ in range(30):
        try:
            requests.get(f"{OATHKEEPER}/health/ready", timeout=5)
            break
        except requests.ConnectionError:
            time.sleep(2)
    answer = decision("/user1/lab", login["access_token"])
    record("Oathkeeper allows user1's login token on /user1/",
           answer.status_code == 200, f"HTTP {answer.status_code}")
    record("header mutator: X-User-Name and X-User-Subject",
           answer.headers.get("X-User-Name") == "user1"
           and answer.headers.get("X-User-Subject")
           == str(token_info(login["access_token"])
                  .json()["resource_owner_id"]),
           f"X-User-Name {answer.headers.get('X-User-Name')}, "
           f"X-User-Groups {answer.headers.get('X-User-Groups')}")
    extra = SEEN[-1]["subject"]["extra"] if SEEN else {}
    save("oathkeeper-authz-payload", SEEN[-1] if SEEN else {},
         note="what login-relay's /authz/workspace/<user> receives")
    record("fields in Oathkeeper .Extra", "username" in extra,
           f"{sorted(extra)}")
    answer = decision("/user2/lab", login["access_token"])
    record("user1's token on /user2/ not allowed",
           answer.status_code != 200, f"HTTP {answer.status_code} "
           f"{answer.headers.get('Location', '')[:60]}")
    answer = decision("/user1/lab", backup["access_token"])
    record("workspace-backup token is not a session",
           answer.status_code != 200, f"HTTP {answer.status_code}")
    server.shutdown()


def main() -> int:
    """Run every check, write the summary, return non-zero on a failure."""
    wait_for_api()
    version = api("GET", "/version").json()
    record("GitLab version", True, f"{version.get('version')} "
           f"{version.get('revision')}")
    register_apps()
    check_discovery()
    browser = Browser("user1")
    login = check_login_client(browser)
    check_pkce(browser)
    check_redirect_uris(browser)
    check_scopes(browser)
    backup = connect(browser)
    save("token-workspace-backup", backup | {})
    record("workspace-backup token: openid write_repository",
           backup.get("scope") == "openid write_repository",
           f"scope {backup.get('scope')}, id_token "
           f"{'id_token' in backup}")
    check_token_answers(login, backup)
    check_introspection_endpoint(login, backup)
    check_git(login, backup)
    check_oathkeeper(login, backup)
    check_refresh(backup)
    check_revoke(browser)
    check_consent_denied()
    check_blocked_user()
    return finish("s3-gitlab")


if __name__ == "__main__":
    sys.exit(main())
