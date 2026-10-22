"""Spike S3: checks the GitLab OAuth behaviour the storage design relies on.

Runs against the GitLab of compose.yml after setup.sh. Prints one line
per check and writes redacted provider responses to recorded/ for the
login-relay contract tests (T303). Needs requests, pyjwt
and playwright (sign-in and consent run in headless Chromium). Run
with: python3 -I probe.py
"""

# The spike's dependencies are not in the CI lint environment.
# pylint: disable=duplicate-code,import-error

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import requests
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

BASE = "http://localhost:8929"
HERE = Path(__file__).resolve().parent
STATE = json.loads(Path(os.environ.get("STATE", HERE / "state.json")).read_text(encoding="utf-8"))
RECORDED = HERE / "recorded"
SHOTS = RECORDED / "raw"
BACKUP_REDIRECT = "https://dtaas.example.org/login-relay/oauth/gitlab/callback"
LOGIN_REDIRECT = "https://dtaas.example.org/login-relay/callback"
TOKEN_KEYS = ("access_token", "refresh_token", "id_token")

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    """Records and prints one check."""
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)
    return ok


def note(name: str, detail: str) -> None:
    """Prints an observation that is not pass or fail."""
    print(f"NOTE  {name}  {detail}", flush=True)


def redact(value):
    """Replaces secrets in a provider response with placeholders."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in TOKEN_KEYS and isinstance(item, str):
                out[key] = f"<{key}>"
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def record(name: str, status: int, body) -> None:
    """Saves a redacted response for contract tests."""
    RECORDED.mkdir(exist_ok=True)
    (RECORDED / f"{name}.json").write_text(
        json.dumps({"status": status, "body": redact(body)}, indent=2,
                   sort_keys=True) + "\n", encoding="utf-8")


def pkce_pair() -> tuple[str, str]:
    """Returns an RFC 7636 verifier and its S256 challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


CHROMIUM = os.environ.get("CHROMIUM", str(next(Path.home().glob(
    ".cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell"),
    "")))


class BrowserUser:  # pylint: disable=too-few-public-methods
    """One user's headless Chromium context, signed in to GitLab.

    Requests to any host but GitLab are answered with a stub page and
    recorded, so the redirect GitLab sends the browser to is captured
    without a DTaaS deployment.
    """

    def __init__(self, browser, username: str):
        self.username = username
        self.context = browser.new_context()
        self.page = self.context.new_page()
        self.captured: str | None = None
        # A route alone misses the redirect after a form post, so the
        # request event records the address and the route stubs the page.
        self.context.on("request", self._seen)
        self.context.route(re.compile(r"^https?://(?!localhost:8929/).*"),
                           self._capture)

    def _seen(self, request) -> None:
        if (request.is_navigation_request() and self.captured is None
                and not request.url.startswith("http://localhost:8929/")):
            self.captured = request.url
        self._sign_in()

    def _capture(self, route) -> None:
        if route.request.is_navigation_request() and self.captured is None:
            self.captured = route.request.url
        route.fulfill(status=200, content_type="text/html", body="stub")

    def _sign_in(self) -> None:
        page = self.page
        page.goto(f"{BASE}/users/sign_in")
        page.fill("#user_login", self.username)
        page.fill("#user_password", STATE["password"])
        page.locator("[data-testid=sign-in-button], form#new_user "
                     "button[type=submit], form#new_user input[type=submit]"
                     ).first.click()
        page.wait_for_load_state("networkidle")
        if "/users/sign_in" in page.url:
            raise RuntimeError(f"sign-in failed for {self.username}: {page.url}")

    def authorize(self, params: dict) -> dict:
        """Opens /oauth/authorize; clicks Authorize if consent is asked.

        Returns {"consent": bool, "location": str | None, "status": int,
        "html": str}; location is the off-GitLab address the browser was
        sent to, if any.
        """
        self.captured = None
        # A fresh page per request, so a stubbed or failed redirect from
        # the previous one cannot interrupt this navigation.
        self.page.close()
        self.page = self.context.new_page()
        try:
            reply = self.page.goto(f"{BASE}/oauth/authorize?{urlencode(params)}")
        except PlaywrightError:
            # An immediate redirect to the unresolvable DTaaS address
            # fails the navigation after the request event recorded it.
            if self.captured is None:
                raise
            reply = None
        consent = False
        button = self.page.get_by_role("button", name=re.compile(r"^Authorize"))
        if self.captured is None and button.count():
            consent = True
            SHOTS.mkdir(parents=True, exist_ok=True)
            self.page.screenshot(path=str(SHOTS / f"consent-{self.username}.png"))
            button.first.click()
            self.page.wait_for_load_state("networkidle")
        return {"consent": consent, "status": reply.status if reply else 0,
                "location": self.captured, "html": self.page.content()}


def authorize(user: BrowserUser, params: dict) -> dict:
    """Runs the browser part of an authorization request."""
    return user.authorize(params)


def code_from(location: str | None, redirect: str) -> str | None:
    """Returns the code when location is the registered redirect URI."""
    if not location or not location.startswith(redirect + "?"):
        return None
    return parse_qs(urlparse(location).query).get("code", [None])[0]


def backup_params(challenge: str | None, **extra) -> dict:
    """Authorize parameters for the public workspace-backup application."""
    params = {"client_id": STATE["backup"]["application_id"],
              "redirect_uri": BACKUP_REDIRECT, "response_type": "code",
              "scope": "openid write_repository",
              "state": "user1." + secrets.token_urlsafe(8)}
    if challenge:
        params.update(code_challenge=challenge, code_challenge_method="S256")
    params.update(extra)
    return params


def token(data: dict) -> requests.Response:
    """POST /oauth/token."""
    return requests.post(f"{BASE}/oauth/token", data=data, timeout=30)


def redeem_backup(code: str, verifier: str | None,
                  redirect: str = BACKUP_REDIRECT) -> requests.Response:
    """Redeems a workspace-backup code as a public client."""
    data = {"grant_type": "authorization_code", "code": code,
            "redirect_uri": redirect,
            "client_id": STATE["backup"]["application_id"]}
    if verifier is not None:
        data["code_verifier"] = verifier
    return token(data)


def refresh_backup(refresh: str) -> requests.Response:
    """Refreshes as the public workspace-backup client."""
    return token({"grant_type": "refresh_token", "refresh_token": refresh,
                  "client_id": STATE["backup"]["application_id"]})


def bearer(path: str, access: str) -> requests.Response:
    """GET with a bearer token."""
    return requests.get(f"{BASE}{path}", timeout=30,
                        headers={"Authorization": f"Bearer {access}"})


def connect_backup(session: BrowserUser) -> tuple[dict, dict]:
    """Full workspace-backup connect; returns (authorize, token reply)."""
    verifier, challenge = pkce_pair()
    auth = authorize(session, backup_params(challenge))
    code = code_from(auth["location"], BACKUP_REDIRECT)
    reply = redeem_backup(code, verifier)
    reply.raise_for_status()
    return auth, reply.json()


def git_push(access: str, path: str, label: str) -> tuple[bool, str]:
    """Pushes one commit over HTTP with oauth2:<token>; returns (ok, stderr)."""
    with tempfile.TemporaryDirectory() as tmp:
        url = f"http://oauth2:{access}@localhost:8929/{path}.git"
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        clone = subprocess.run(["git", "clone", "-q", url, tmp + "/r"],
                               capture_output=True, text=True, env=env,
                               timeout=120, check=False)
        if clone.returncode:
            return False, "clone: " + clone.stderr.replace(access, "<token>")[-200:]
        repo = tmp + "/r"
        Path(repo, f"{label}.txt").write_text(f"{time.time()}\n", encoding="utf-8")
        for cmd in (["git", "add", "-A"],
                    ["git", "-c", "user.name=spike", "-c", "user.email=s@x",
                     "commit", "-qm", label]):
            subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
        push = subprocess.run(["git", "push", "-q", "origin", "HEAD"], cwd=repo,
                              capture_output=True, text=True, env=env,
                              timeout=120, check=False)
        return push.returncode == 0, push.stderr.replace(access, "<token>")[-200:]


def root(method: str, path: str, **kwargs) -> requests.Response:
    """Admin API call as root."""
    return requests.request(method, f"{BASE}/api/v4{path}", timeout=30,
                            headers={"PRIVATE-TOKEN": STATE["root_token"]},
                            **kwargs)


def main() -> int:
    """Runs every check in one headless Chromium; 1 when any fails."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=CHROMIUM, headless=True,
            args=["--disable-gpu", "--disable-dev-shm-usage"])
        try:
            return run(browser)
        finally:
            browser.close()


def run(browser) -> int:  # pylint: disable=too-many-locals,too-many-statements
    """The checks."""
    version = root("GET", "/version").json()
    note("gitlab_version", f"{version.get('version')} {version.get('revision')}")
    backup_uid = STATE["backup"]["application_id"]
    login_uid = STATE["login"]["application_id"]
    check("backup_app_is_public", STATE["backup"].get("confidential") is False,
          f"confidential={STATE['backup'].get('confidential')}")
    check("backup_app_scopes", STATE["backup"].get("scopes") is None
          or "write_repository" in str(STATE["backup"].get("scopes")),
          str(STATE["backup"].get("scopes")))

    user1 = BrowserUser(browser, "user1")

    # --- PKCE on the public application --------------------------------
    verifier, challenge = pkce_pair()
    first = authorize(user1, backup_params(challenge))
    code = code_from(first["location"], BACKUP_REDIRECT)
    check("public_authorize_returns_code", code is not None,
          f"consent_shown={first['consent']} status={first['status']}")
    state_back = parse_qs(urlparse(first["location"] or "").query).get("state")
    check("state_returned_unchanged", bool(state_back)
          and state_back[0].startswith("user1."), str(state_back))
    reply = redeem_backup(code, verifier)
    body = reply.json()
    record("backup_token_authorization_code", reply.status_code, body)
    check("public_redeem_with_verifier_no_secret", reply.status_code == 200,
          f"status={reply.status_code} keys={sorted(body)}")
    access1, refresh1 = body.get("access_token"), body.get("refresh_token")
    check("access_token_expires_in_7200", body.get("expires_in") == 7200,
          f"expires_in={body.get('expires_in')}")
    check("refresh_token_returned", bool(refresh1))
    check("scope_granted", body.get("scope") == "openid write_repository",
          f"scope={body.get('scope')!r}")
    note("backup_code_reply_has_id_token", str("id_token" in body))
    check("backup_access_token_opaque", access1 is not None
          and access1.count(".") != 2, f"len={len(access1 or '')}")
    check("code_single_use", redeem_backup(code, verifier).status_code in (400, 401))

    for label, use_verifier in (("no_verifier", None), ("wrong_verifier", "x" * 43)):
        _, chal = pkce_pair()
        auth = authorize(user1, backup_params(chal))
        reply = redeem_backup(code_from(auth["location"], BACKUP_REDIRECT),
                              use_verifier)
        record(f"backup_redeem_{label}", reply.status_code, reply.json())
        check(f"public_redeem_{label}_refused", reply.status_code in (400, 401),
              f"status={reply.status_code} body={reply.json()}")

    auth = authorize(user1, backup_params(None))
    plain_code = code_from(auth["location"], BACKUP_REDIRECT)
    if plain_code:
        reply = redeem_backup(plain_code, None)
        note("public_without_pkce", f"authorize gave a code; redeem without "
             f"verifier -> {reply.status_code}")
    else:
        note("public_without_pkce", f"authorize refused: status={auth['status']} "
             f"location={auth['location']}")

    # --- Exact redirect URIs ---------------------------------------------
    variants = {
        "trailing_slash": BACKUP_REDIRECT + "/",
        "extra_query": BACKUP_REDIRECT + "?x=1",
        "sub_path": BACKUP_REDIRECT + "/x",
        "http_scheme": BACKUP_REDIRECT.replace("https:", "http:"),
        "upper_host": BACKUP_REDIRECT.replace("dtaas.example.org", "DTAAS.example.org"),
        "other_host": BACKUP_REDIRECT.replace("dtaas.example.org", "evil.example.org"),
        "parent_path": "https://dtaas.example.org/login-relay/oauth/gitlab",
        "login_callback": LOGIN_REDIRECT,
    }
    for label, uri in variants.items():
        _, chal = pkce_pair()
        auth = authorize(user1, backup_params(chal, redirect_uri=uri))
        loc = auth["location"] or ""
        leaked = "code=" in loc and urlparse(loc).netloc.lower() != "localhost:8929"
        check(f"redirect_refused_{label}", not leaked,
              f"status={auth['status']} location={loc[:90]}")

    _, chal = pkce_pair()
    verifier2, chal2 = pkce_pair()
    auth = authorize(user1, backup_params(chal2))
    reply = redeem_backup(code_from(auth["location"], BACKUP_REDIRECT), verifier2,
                          redirect=BACKUP_REDIRECT + "/")
    check("redeem_needs_same_redirect_uri", reply.status_code in (400, 401),
          f"status={reply.status_code} body={reply.json()}")

    # --- Consent ------------------------------------------------------------
    note("backup_consent_first_connect", str(first["consent"]))
    again = authorize(user1, backup_params(pkce_pair()[1]))
    note("backup_consent_second_connect", str(again["consent"]))

    # --- token/info and userinfo ----------------------------------------
    info = bearer("/oauth/token/info", access1)
    record("backup_token_info", info.status_code, info.json())
    ibody = info.json()
    check("token_info_fields",
          {"resource_owner_id", "scope", "expires_in", "application",
           "created_at"} <= set(ibody), f"keys={sorted(ibody)}")
    check("token_info_application_uid",
          (ibody.get("application") or {}).get("uid") == backup_uid,
          f"application={ibody.get('application')}")
    check("token_info_owner_is_user1",
          ibody.get("resource_owner_id") == STATE["user1_id"],
          f"resource_owner_id={ibody.get('resource_owner_id')}")
    note("token_info_expires_in", f"{ibody.get('expires_in')} "
         f"(expires_in_seconds={ibody.get('expires_in_seconds')})")
    info_param = requests.get(f"{BASE}/oauth/token/info",
                              params={"access_token": access1}, timeout=30)
    note("token_info_query_param", f"status={info_param.status_code}")

    userinfo = bearer("/oauth/userinfo", access1)
    record("backup_userinfo", userinfo.status_code, userinfo.json())
    ubody = userinfo.json()
    check("userinfo_nickname_is_username", ubody.get("nickname") == "user1",
          f"keys={sorted(ubody)}")
    check("userinfo_sub_is_user_id", str(ubody.get("sub")) == str(STATE["user1_id"]),
          f"sub={ubody.get('sub')!r}")
    note("userinfo_preferred_username", repr(ubody.get("preferred_username")))
    note("userinfo_groups", repr(ubody.get("groups")))

    bad = bearer("/oauth/token/info", "not-a-token")
    record("token_info_invalid", bad.status_code, bad.json())
    check("token_info_invalid_401", bad.status_code == 401, f"body={bad.json()}")
    bad_ui = bearer("/oauth/userinfo", "not-a-token")
    record("userinfo_invalid", bad_ui.status_code,
           bad_ui.json() if bad_ui.text.strip().startswith("{") else bad_ui.text)
    check("userinfo_invalid_401", bad_ui.status_code == 401)

    intro = requests.post(f"{BASE}/oauth/introspect", data={"token": access1},
                          timeout=30)
    note("standard_introspect_unauthenticated", f"status={intro.status_code}")
    intro = requests.post(f"{BASE}/oauth/introspect", data={"token": access1},
                          auth=(login_uid, STATE["login"]["secret"]), timeout=30)
    note("standard_introspect_with_login_app",
         f"status={intro.status_code} body={intro.text[:160]}")
    record("introspect_with_login_app", intro.status_code,
           intro.json() if intro.text.strip().startswith("{") else intro.text)

    # --- Login application (confidential, openid, PKCE, nonce) ----------
    lverifier, lchallenge = pkce_pair()
    nonce = secrets.token_urlsafe(12)
    lparams = {"client_id": login_uid, "redirect_uri": LOGIN_REDIRECT,
               "response_type": "code", "scope": "openid",
               "state": secrets.token_urlsafe(8), "nonce": nonce,
               "code_challenge": lchallenge, "code_challenge_method": "S256"}
    lauth = authorize(user1, lparams)
    note("login_consent_first", str(lauth["consent"]))
    lcode = code_from(lauth["location"], LOGIN_REDIRECT)
    lreply = token({"grant_type": "authorization_code", "code": lcode,
                    "redirect_uri": LOGIN_REDIRECT, "client_id": login_uid,
                    "client_secret": STATE["login"]["secret"],
                    "code_verifier": lverifier})
    lbody = lreply.json()
    record("login_token_authorization_code", lreply.status_code, lbody)
    check("confidential_redeem_with_pkce", lreply.status_code == 200
          and "id_token" in lbody, f"keys={sorted(lbody)}")
    check("login_expires_in_7200", lbody.get("expires_in") == 7200,
          f"expires_in={lbody.get('expires_in')}")
    keys = requests.get(f"{BASE}/oauth/discovery/keys", timeout=30).json()
    record("discovery_keys", 200, keys)
    header = jwt.get_unverified_header(lbody["id_token"])
    jwk = next(k for k in keys["keys"] if k.get("kid") == header.get("kid"))
    claims = jwt.decode(lbody["id_token"],
                        key=jwt.PyJWK(jwk).key, algorithms=[header["alg"]],
                        audience=login_uid, issuer=BASE)
    record("login_id_token_claims", 200, {"header": header, "claims": claims})
    check("id_token_verifies_iss_aud", True,
          f"alg={header['alg']} iss={claims['iss']} aud={claims['aud']}")
    check("id_token_nonce_echoed", claims.get("nonce") == nonce)
    check("id_token_lifetime_120s", claims["exp"] - claims["iat"] == 120,
          f"exp-iat={claims['exp'] - claims['iat']}")
    note("id_token_claims", f"keys={sorted(claims)} nickname={claims.get('nickname')!r}"
         f" preferred_username={claims.get('preferred_username')!r}")
    discovery = requests.get(f"{BASE}/.well-known/openid-configuration",
                             timeout=30).json()
    record("openid_configuration", 200, discovery)
    note("discovery", f"issuer={discovery.get('issuer')} "
         f"pkce={discovery.get('code_challenge_methods_supported')} "
         f"revocation={discovery.get('revocation_endpoint')} "
         f"introspection={discovery.get('introspection_endpoint')}")

    # Wrong verifier on the confidential app.
    _, wchal = pkce_pair()
    wauth = authorize(user1, {**lparams, "code_challenge": wchal,
                              "state": secrets.token_urlsafe(8)})
    wreply = token({"grant_type": "authorization_code",
                    "code": code_from(wauth["location"], LOGIN_REDIRECT),
                    "redirect_uri": LOGIN_REDIRECT, "client_id": login_uid,
                    "client_secret": STATE["login"]["secret"],
                    "code_verifier": "y" * 43})
    check("confidential_wrong_verifier_refused", wreply.status_code in (400, 401),
          f"status={wreply.status_code}")

    linfo = bearer("/oauth/token/info", lbody["access_token"]).json()
    record("login_token_info", 200, linfo)
    check("token_info_tells_apps_apart",
          (linfo.get("application") or {}).get("uid") == login_uid
          and linfo.get("application") != ibody.get("application"))

    _, schal = pkce_pair()
    sauth = authorize(user1, {**lparams, "scope": "openid write_repository",
                              "code_challenge": schal,
                              "state": secrets.token_urlsafe(8)})
    check("login_app_cannot_get_write_repository",
          code_from(sauth["location"], LOGIN_REDIRECT) is None,
          f"status={sauth['status']} location={(sauth['location'] or '')[:100]}")

    # --- git over HTTP ------------------------------------------------------
    ok, err = git_push(access1, "user1/thesis", "backup-token")
    check("git_push_with_write_repository_token", ok, err)
    ok, err = git_push(lbody["access_token"], "user1/thesis", "login-token")
    check("git_push_with_openid_token_refused", not ok, err.strip()[-120:])
    user2 = BrowserUser(browser, "user2")
    _, u2body = connect_backup(user2)
    ok, err = git_push(u2body["access_token"], "user1/thesis", "user2-token")
    check("git_push_other_users_repo_refused", not ok, err.strip()[-120:])

    # --- Refresh: rotation and ID token ----------------------------------
    reply = refresh_backup(refresh1)
    rbody = reply.json()
    record("backup_token_refresh", reply.status_code, rbody)
    check("public_refresh_no_secret", reply.status_code == 200,
          f"status={reply.status_code}")
    access2, refresh2 = rbody.get("access_token"), rbody.get("refresh_token")
    check("refresh_rotates_refresh_token", refresh2 and refresh2 != refresh1)
    check("no_id_token_on_refresh", "id_token" not in rbody, f"keys={sorted(rbody)}")
    check("refreshed_expires_in_7200", rbody.get("expires_in") == 7200)
    note("old_access_after_refresh",
         f"token/info -> {bearer('/oauth/token/info', access1).status_code}")
    # Old refresh token before the new access token is used.
    replay = refresh_backup(refresh1)
    note("old_refresh_before_new_access_used",
         f"status={replay.status_code} body={str(redact(replay.json()))[:120]}")
    if replay.status_code == 200:
        access2, refresh2 = replay.json()["access_token"], replay.json()["refresh_token"]
    used = bearer("/oauth/token/info", access2)
    note("new_access_token_used", f"token/info -> {used.status_code}")
    replay = refresh_backup(refresh1)
    record("backup_refresh_reused", replay.status_code, replay.json())
    check("old_refresh_refused_after_new_access_used",
          replay.status_code in (400, 401), f"status={replay.status_code} "
          f"body={replay.json()}")
    note("old_access_after_new_used",
         f"token/info -> {bearer('/oauth/token/info', access1).status_code}")
    # Rotation lost: the next refresh with the newest token still works.
    reply = refresh_backup(refresh2)
    check("chain_continues_with_newest", reply.status_code == 200)
    access3, refresh3 = reply.json()["access_token"], reply.json()["refresh_token"]

    # --- Blocking ---------------------------------------------------------
    root("POST", f"/users/{STATE['user1_id']}/block")
    note("blocked_token_info",
         f"{bearer('/oauth/token/info', access3).status_code}")
    note("blocked_userinfo", f"{bearer('/oauth/userinfo', access3).status_code}")
    blocked = refresh_backup(refresh3)
    record("backup_refresh_blocked_user", blocked.status_code, blocked.json())
    check("blocked_user_refresh_refused", blocked.status_code in (400, 401),
          f"status={blocked.status_code} body={blocked.json()}")
    ok, err = git_push(access3, "user1/thesis", "blocked")
    check("blocked_user_push_refused", not ok, err.strip()[-120:])
    root("POST", f"/users/{STATE['user1_id']}/unblock")
    after = refresh_backup(refresh3)
    note("refresh_after_unblock", f"status={after.status_code}")

    # --- Revocation by a public client ---------------------------------
    user1 = BrowserUser(browser, "user1")
    _, fresh = connect_backup(user1)
    rev = requests.post(f"{BASE}/oauth/revoke", timeout=30, data={
        "token": fresh["refresh_token"], "client_id": backup_uid})
    record("backup_revoke", rev.status_code, rev.json() if rev.text.strip() else "")
    check("public_revoke_200", rev.status_code == 200, f"status={rev.status_code}")
    check("revoked_refresh_refused",
          refresh_backup(fresh["refresh_token"]).status_code in (400, 401))
    revoked_info = bearer("/oauth/token/info", fresh["access_token"])
    record("token_info_revoked", revoked_info.status_code, revoked_info.json())
    check("access_token_dies_with_refresh_revoke",
          revoked_info.status_code == 401, f"status={revoked_info.status_code}")
    _, other = connect_backup(user1)
    rev = requests.post(f"{BASE}/oauth/revoke", timeout=30, data={
        "token": other["refresh_token"], "client_id": login_uid})
    note("revoke_with_other_client_id", f"status={rev.status_code}; refresh then "
         f"-> {refresh_backup(other['refresh_token']).status_code}")

    # --- Internal address ---------------------------------------------
    internal = subprocess.run(
        ["docker", "compose", "-f", str(HERE / "compose.yml"), "exec", "-T",
         "gitlab", "curl", "-fsS", "http://gitlab:8929/.well-known/openid-configuration"],
        capture_output=True, text=True, timeout=60, check=False)
    if internal.returncode == 0:
        issuer = json.loads(internal.stdout).get("issuer")
        check("issuer_fixed_by_external_url", issuer == BASE,
              f"issuer via http://gitlab:8929 = {issuer}")
    else:
        note("internal_address", internal.stderr[-200:])

    failed = [name for name, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
    if failed:
        print("failed:", ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
