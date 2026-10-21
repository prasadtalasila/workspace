"""Spike S4: Keycloak behaviour for login-relay and workspace backups.

Runs next to the test compose's Keycloak and Traefik, with
``KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true``. Reaches Keycloak's public URL
through Traefik as a browser does (``KEYCLOAK_PUBLIC_URL``) and its
internal URL directly as login-relay and workspace-admin will
(``KEYCLOAK_INTERNAL_URL``). Creates the realm and the ``dtaas-workspace``
and ``workspace-backup`` clients of
``docs/design/storage/STORAGE_KEYCLOAK.md`` through the admin API, drives
the browser steps over HTTP, and checks the backchannel URLs and issuer,
PKCE, consent, offline access, the offline session maximum, rotation,
introspection by login-relay's client and revocation. Prints one line per
check; Keycloak's answers, redacted, go to ``/spike-out/recorded``.

Usage: ``python spike_s4_keycloak.py``.
"""

# jwt and requests are installed only in the spike image.
# pylint: disable=import-error

from __future__ import annotations

import os
import re
import secrets
import sys
import time
from typing import Any
from urllib.parse import urlencode

import jwt
import requests

from spike_common import (TIMEOUT, find_form, finish, forms, jwt_claims,
                          oauth_error, pkce_pair, query, record, save)

PUBLIC = os.environ.get("KEYCLOAK_PUBLIC_URL", "http://dtaas.test/auth")
INTERNAL = os.environ.get("KEYCLOAK_INTERNAL_URL",
                          "http://keycloak:8080/auth")
REALM = os.environ.get("KEYCLOAK_REALM", "dtaas")
ADMIN = os.environ["KEYCLOAK_ADMIN"]
ADMIN_PASSWORD = os.environ["KEYCLOAK_ADMIN_PASSWORD"]
PASSWORD = os.environ["SPIKE_USER_PASSWORD"]
DTAAS = os.environ.get("DTAAS_URL", "http://dtaas.test")
LOGIN_REDIRECT = f"{DTAAS}/login-relay/callback"
BACKUP_REDIRECT = f"{DTAAS}/login-relay/oauth/keycloak/callback"
ISSUER = f"{PUBLIC}/realms/{REALM}"
OIDC = f"{INTERNAL}/realms/{REALM}/protocol/openid-connect"
DAY = 86400
OFFLINE_IDLE = 30 * DAY
OFFLINE_MAX = 180 * DAY

CONSENT_ACTION = r"login-actions/(consent|required-action)"

LOGIN_SECRET: dict[str, str] = {}


# --- Admin API --------------------------------------------------------------


def admin_token() -> str:
    """Return an access token of Keycloak's bootstrap admin."""
    answer = requests.post(
        f"{INTERNAL}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": ADMIN, "password": ADMIN_PASSWORD},
        timeout=TIMEOUT)
    answer.raise_for_status()
    return answer.json()["access_token"]


def api(method: str, path: str, **kwargs: Any) -> requests.Response:
    """Call the admin REST API of the spike realm."""
    return requests.request(
        method, f"{INTERNAL}/admin/realms/{REALM}{path}",
        headers={"Authorization": f"Bearer {admin_token()}"},
        timeout=TIMEOUT, **kwargs)


def set_realm(**settings: Any) -> None:
    """Change realm settings."""
    api("PUT", "", json=settings).raise_for_status()


def client_uuid(client_id: str) -> str:
    """Return the internal id of a client."""
    return api("GET", "/clients",
               params={"clientId": client_id}).json()[0]["id"]


def user_uuid(name: str) -> str:
    """Return the internal id of a user."""
    return api("GET", "/users", params={"username": name,
                                        "exact": "true"}).json()[0]["id"]


def add_audience(client_id: str, audience: str) -> None:
    """Put ``audience`` in the access tokens of ``client_id``."""
    api("POST", f"/clients/{client_uuid(client_id)}/protocol-mappers/models",
        json={"name": f"{audience}-audience", "protocol": "openid-connect",
              "protocolMapper": "oidc-audience-mapper",
              "config": {"included.client.audience": audience,
                         "access.token.claim": "true",
                         "id.token.claim": "false",
                         "introspection.token.claim": "true"}},
        ).raise_for_status()


def setup_realm() -> None:
    """Create the realm, both clients and two users afresh."""
    headers = {"Authorization": f"Bearer {admin_token()}"}
    requests.delete(f"{INTERNAL}/admin/realms/{REALM}", headers=headers,
                    timeout=TIMEOUT)
    requests.post(f"{INTERNAL}/admin/realms", headers=headers, json={
        "realm": REALM, "enabled": True,
        "offlineSessionIdleTimeout": OFFLINE_IDLE,
        "offlineSessionMaxLifespanEnabled": True,
        "offlineSessionMaxLifespan": OFFLINE_MAX,
    }, timeout=TIMEOUT).raise_for_status()
    api("POST", "/clients", json={
        "clientId": "dtaas-workspace", "protocol": "openid-connect",
        "publicClient": False, "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": [LOGIN_REDIRECT],
    }).raise_for_status()
    api("POST", "/clients", json={
        "clientId": "workspace-backup", "protocol": "openid-connect",
        "publicClient": True, "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
        "consentRequired": True,
        "redirectUris": [BACKUP_REDIRECT],
        "attributes": {"pkce.code.challenge.method": "S256"},
    }).raise_for_status()
    # As KEYCLOAK_SETUP.md: the login client is in its own tokens' aud.
    add_audience("dtaas-workspace", "dtaas-workspace")
    secret = api("GET", f"/clients/{client_uuid('dtaas-workspace')}"
                        "/client-secret").json()
    LOGIN_SECRET["value"] = secret["value"]
    for name in ("user1", "user2"):
        api("POST", "/users", json={
            "username": name, "enabled": True, "emailVerified": True,
            "email": f"{name}@example.org", "firstName": name,
            "lastName": "Spike",
            "credentials": [{"type": "password", "value": PASSWORD,
                             "temporary": False}],
        }).raise_for_status()
    realm = api("GET", "").json()
    save("admin-realm-offline-settings", {
        k: realm.get(k) for k in (
            "offlineSessionIdleTimeout", "offlineSessionMaxLifespanEnabled",
            "offlineSessionMaxLifespan", "accessTokenLifespan",
            "revokeRefreshToken", "refreshTokenMaxReuse",
            "ssoSessionIdleTimeout", "ssoSessionMaxLifespan")})
    record("realm keeps 30-day idle and 180-day offline maximum",
           realm.get("offlineSessionMaxLifespanEnabled") is True
           and realm.get("offlineSessionMaxLifespan") == OFFLINE_MAX
           and realm.get("offlineSessionIdleTimeout") == OFFLINE_IDLE,
           f"max {realm.get('offlineSessionMaxLifespan')}, "
           f"idle {realm.get('offlineSessionIdleTimeout')}")
    backup = api("GET", f"/clients/{client_uuid('workspace-backup')}").json()
    record("workspace-backup: public, consent, PKCE S256",
           backup["publicClient"] and backup["consentRequired"]
           and backup["attributes"].get("pkce.code.challenge.method")
           == "S256",
           f"optional scopes {backup.get('optionalClientScopes')}")


# --- Browser steps over HTTP ------------------------------------------------


class Browser:
    """A browser with a Keycloak SSO session cookie jar."""

    def __init__(self, user: str) -> None:
        self.user = user
        self.session = requests.Session()
        self.signed_in = False

    def follow(self, page: requests.Response) -> requests.Response:
        """Follow redirects inside Keycloak; stop at any other address."""
        while page.is_redirect and page.headers["Location"].startswith(
                PUBLIC):
            page = self.session.get(page.headers["Location"],
                                    allow_redirects=False, timeout=TIMEOUT)
        return page

    def authorize(self, params: dict[str, str]) -> requests.Response:
        """Open the public authorize URL; sign in if Keycloak asks."""
        page = self.follow(self.session.get(
            f"{ISSUER}/protocol/openid-connect/auth?{urlencode(params)}",
            allow_redirects=False, timeout=TIMEOUT))
        if page.status_code == 200 and "kc-form-login" in page.text:
            form = find_form(page, r"login-actions/authenticate")
            form["fields"].update({"username": self.user,
                                   "password": PASSWORD})
            page = self.follow(self.session.post(
                form["action"], data=form["fields"], allow_redirects=False,
                timeout=TIMEOUT))
            self.signed_in = True
        return page

    def answer_consent(self, page: requests.Response,
                       accept: bool) -> requests.Response:
        """Press Yes or No on Keycloak's consent page."""
        form = find_form(page, CONSENT_ACTION)
        button = "accept" if accept else "cancel"
        data = form["fields"] | {button: "Yes" if accept else "No"}
        return self.follow(self.session.post(
            form["action"], data=data, allow_redirects=False,
            timeout=TIMEOUT))


def auth_params(  # pylint: disable=too-many-arguments
        challenge: str | None, *, client: str = "workspace-backup",
        method: str = "S256", scope: str = "openid offline_access",
        redirect: str = BACKUP_REDIRECT,
        user: str = "user1") -> dict[str, str]:
    """Authorize parameters of STORAGE_KEYCLOAK step 4."""
    params = {"client_id": client, "redirect_uri": redirect,
              "response_type": "code", "scope": scope,
              "state": f"{user}.{secrets.token_urlsafe(32)}",
              "nonce": secrets.token_urlsafe(16)}
    if challenge is not None:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = method
    return params


def is_consent(page: requests.Response) -> bool:
    """Whether ``page`` is Keycloak's consent page."""
    return page.status_code == 200 and any(
        re.search(CONSENT_ACTION, f["action"]) for f in forms(page))


def get_code(browser: Browser, params: dict[str, str],
             accept: bool = True) -> tuple[dict[str, str], bool]:
    """Run authorize to the callback; return its query and consent shown."""
    page = browser.authorize(params)
    consent = is_consent(page)
    if consent:
        page = browser.answer_consent(page, accept)
    location = page.headers.get("Location", "")
    if not location.startswith(params["redirect_uri"]):
        raise RuntimeError(f"no redirect to the callback: HTTP "
                           f"{page.status_code} {location[:100]} "
                           f"{page.text[:200] if not location else ''}")
    got = query(location)
    if got.get("state") != params["state"]:
        raise RuntimeError("state not returned unchanged")
    return got, consent


def token(data: dict[str, str], base: str = OIDC) -> requests.Response:
    """POST to the token endpoint (internal by default)."""
    return requests.post(f"{base}/token", data=data, timeout=TIMEOUT)


def redeem(code: str, verifier: str | None, *,
           client: str = "workspace-backup",
           redirect: str = BACKUP_REDIRECT,
           base: str = OIDC) -> requests.Response:
    """Redeem a code as workspace-admin (public) or login-relay does."""
    data = {"grant_type": "authorization_code", "code": code,
            "client_id": client, "redirect_uri": redirect}
    if verifier is not None:
        data["code_verifier"] = verifier
    if client == "dtaas-workspace":
        data["client_secret"] = LOGIN_SECRET["value"]
    return token(data, base)


def connect(browser: Browser) -> dict[str, Any]:
    """Complete the workspace-backup login; return the token answer."""
    verifier, challenge = pkce_pair()
    got, _ = get_code(browser, auth_params(challenge, user=browser.user))
    answer = redeem(got["code"], verifier)
    answer.raise_for_status()
    return answer.json()


def refresh(value: str) -> requests.Response:
    """Refresh as workspace-admin does: public client, no secret."""
    return token({"grant_type": "refresh_token", "refresh_token": value,
                  "client_id": "workspace-backup"})


def introspect(value: str, client: str = "dtaas-workspace",
               secret: str | None = None) -> requests.Response:
    """Introspect with login-relay's confidential client."""
    data = {"token": value, "client_id": client}
    if client == "dtaas-workspace":
        data["client_secret"] = secret or LOGIN_SECRET["value"]
    return requests.post(f"{OIDC}/token/introspect", data=data,
                         timeout=TIMEOUT)


def offline_sessions(user: str) -> list[Any]:
    """The user's offline sessions for workspace-backup."""
    return api("GET", f"/users/{user_uuid(user)}/offline-sessions/"
                      f"{client_uuid('workspace-backup')}").json()


# --- Checks -----------------------------------------------------------------


def check_backchannel() -> None:
    """Internal discovery: internal backchannel URLs, public issuer."""
    inside = requests.get(f"{INTERNAL}/realms/{REALM}/.well-known/"
                          "openid-configuration", timeout=TIMEOUT)
    outside = requests.get(f"{ISSUER}/.well-known/openid-configuration",
                           timeout=TIMEOUT)
    save("discovery-internal", inside)
    save("discovery-public", outside)
    doc, pub = inside.json(), outside.json()
    record("internal discovery: issuer is the public URL",
           doc["issuer"] == ISSUER, doc["issuer"])
    record("internal discovery: authorization_endpoint is public",
           doc["authorization_endpoint"].startswith(PUBLIC),
           doc["authorization_endpoint"])
    for key in ("token_endpoint", "introspection_endpoint", "jwks_uri",
                "userinfo_endpoint"):
        record(f"internal discovery: {key} is internal",
               doc[key].startswith(INTERNAL), doc[key])
    record("internal discovery: revocation_endpoint stays public",
           doc["revocation_endpoint"].startswith(PUBLIC),
           doc["revocation_endpoint"])
    record("internal discovery: end_session_endpoint (informational)", True,
           doc.get("end_session_endpoint", ""))
    record("public discovery: every endpoint public",
           all(str(v).startswith(PUBLIC) for k, v in pub.items()
               if k.endswith(("_endpoint", "_uri"))
               and isinstance(v, str)),
           f"issuer {pub['issuer']}")
    record("advertised PKCE methods",
           "S256" in doc.get("code_challenge_methods_supported", []),
           str(doc.get("code_challenge_methods_supported")))


def check_login_client(browser: Browser) -> dict[str, Any]:
    """dtaas-workspace: code from the public URL redeemed internally."""
    verifier, challenge = pkce_pair()
    params = auth_params(challenge, client="dtaas-workspace",
                         scope="openid profile", redirect=LOGIN_REDIRECT)
    got, consent = get_code(browser, params)
    record("dtaas-workspace has no consent page", not consent)
    answer = redeem(got["code"], verifier, client="dtaas-workspace",
                    redirect=LOGIN_REDIRECT)
    save("token-dtaas-workspace", answer)
    grant = answer.json()
    claims = jwt_claims(grant["access_token"])
    record("code from public authorize redeems at the internal URL",
           answer.status_code == 200, oauth_error(answer)
           if answer.status_code != 200 else "")
    record("access token iss is the public issuer", claims["iss"] == ISSUER,
           claims["iss"])
    keys = jwt.PyJWKClient(f"{OIDC}/certs")
    try:
        jwt.decode(grant["id_token"],
                   keys.get_signing_key_from_jwt(grant["id_token"]).key,
                   algorithms=["RS256"], audience="dtaas-workspace",
                   issuer=ISSUER)
        record("ID token verifies with internal JWKS, public iss", True)
    except jwt.PyJWTError as exc:
        record("ID token verifies with internal JWKS, public iss", False,
               repr(exc))
    record("ID token echoes nonce",
           jwt_claims(grant["id_token"]).get("nonce") == params["nonce"])
    record("login access token lives 5 minutes",
           grant.get("expires_in") == 300,
           f"expires_in {grant.get('expires_in')}")
    return grant


def check_pkce(browser: Browser) -> None:
    """workspace-backup is public and requires PKCE S256."""
    page = browser.authorize(auth_params(None))
    got = query(page.headers.get("Location", ""))
    record("authorize without code_challenge refused",
           got.get("error") == "invalid_request",
           f"{got.get('error')}: {got.get('error_description')}")
    plain = pkce_pair()[0]
    page = browser.authorize(auth_params(plain, method="plain"))
    got = query(page.headers.get("Location", ""))
    record("code_challenge_method=plain refused",
           got.get("error") == "invalid_request",
           f"{got.get('error')}: {got.get('error_description')}")

    verifier, challenge = pkce_pair()
    params = auth_params(challenge)
    got, consent = get_code(browser, params)
    record("consent page on first workspace-backup authorize", consent)
    answer = redeem(got["code"], None)
    save("token-pkce-missing-verifier", answer)
    record("redeem without code_verifier refused",
           answer.status_code == 400, oauth_error(answer))
    got, consent = get_code(browser, auth_params(challenge))
    record("no consent page once granted", not consent)
    answer = redeem(got["code"], pkce_pair()[0])
    save("token-pkce-wrong-verifier", answer)
    record("redeem with wrong code_verifier refused",
           answer.status_code == 400, oauth_error(answer))
    got, _ = get_code(browser, auth_params(challenge))
    answer = redeem(got["code"], verifier)
    record("public redeem with verifier, no secret",
           answer.status_code == 200, oauth_error(answer)
           if answer.status_code != 200 else "")
    again = redeem(got["code"], verifier)
    record("code is single use", again.status_code == 400,
           oauth_error(again))


def check_redirect_uris(browser: Browser) -> None:
    """Only the registered address is accepted, at authorize and token."""
    for variant in (BACKUP_REDIRECT + "/x", BACKUP_REDIRECT + "?next=/x",
                    BACKUP_REDIRECT + "/",
                    "http://evil.test/login-relay/oauth/keycloak/callback",
                    BACKUP_REDIRECT.replace("http:", "https:")):
        page = browser.authorize(auth_params(pkce_pair()[1],
                                             redirect=variant))
        location = page.headers.get("Location", "")
        record(f"redirect_uri refused: {variant[len('http://'):][:60]}",
               not location.startswith(variant), f"HTTP {page.status_code}")
    verifier, challenge = pkce_pair()
    got, _ = get_code(browser, auth_params(challenge))
    answer = redeem(got["code"], verifier, redirect=BACKUP_REDIRECT + "/x")
    record("redeem with another redirect_uri refused",
           answer.status_code == 400, oauth_error(answer))


def check_offline_grant(browser: Browser) -> dict[str, Any]:
    """offline_access gives an offline refresh token; refresh behaviour."""
    grant = connect(browser)
    save("token-workspace-backup", grant)
    access = jwt_claims(grant["access_token"])
    refresh_claims = jwt_claims(grant["refresh_token"])
    save("claims-workspace-backup", {"access": access,
                                     "refresh": refresh_claims})
    record("scope has offline_access",
           "offline_access" in grant.get("scope", "").split(),
           grant.get("scope", ""))
    record("refresh token is an offline token",
           refresh_claims.get("typ") == "Offline",
           f"typ {refresh_claims.get('typ')}, exp "
           f"{refresh_claims.get('exp')}, refresh_expires_in "
           f"{grant.get('refresh_expires_in')}")
    record("access token names the owner (preferred_username)",
           access.get("preferred_username") == "user1",
           f"azp {access.get('azp')}, aud {access.get('aud')}")
    record("backup access token lives 5 minutes",
           grant.get("expires_in") == 300,
           f"expires_in {grant.get('expires_in')}")
    record("ID token in code answer", "id_token" in grant)

    answer = refresh(grant["refresh_token"])
    save("token-refresh-workspace-backup", answer)
    new = answer.json()
    record("public refresh without secret", answer.status_code == 200,
           oauth_error(answer) if answer.status_code != 200 else "")
    record("refresh returns a refresh token",
           bool(new.get("refresh_token")),
           f"changed {new.get('refresh_token') != grant['refresh_token']}")
    record("ID token on refresh (informational)", True,
           f"id_token present {'id_token' in new}")
    reuse = refresh(grant["refresh_token"])
    record("old refresh token with revokeRefreshToken off (informational)",
           True, f"{oauth_error(reuse)}")

    set_realm(revokeRefreshToken=True, refreshTokenMaxReuse=0)
    try:
        grant = connect(browser)
        first = refresh(grant["refresh_token"])
        reuse = refresh(grant["refresh_token"])
        save("token-refresh-reused-rotation-on", reuse)
        record("with revokeRefreshToken on: old refresh token refused",
               first.status_code == 200 and reuse.status_code == 400,
               oauth_error(reuse))
        later = refresh(first.json()["refresh_token"])
        record("with revokeRefreshToken on: newest token after a reuse",
               True, f"informational: {oauth_error(later)}")
    finally:
        set_realm(revokeRefreshToken=False)
    return new


def check_offline_maximum(browser: Browser) -> None:
    """The offline session maximum ends the grant, whatever the use."""
    set_realm(offlineSessionMaxLifespan=20)
    try:
        grant = connect(browser)
        first = refresh(grant["refresh_token"])
        time.sleep(25)
        late = refresh(first.json().get("refresh_token",
                                        grant["refresh_token"]))
        save("token-refresh-offline-max-reached", late)
        record("offline maximum ends a grant in use (20 s probe)",
               first.status_code == 200 and late.status_code == 400,
               oauth_error(late))
    finally:
        set_realm(offlineSessionMaxLifespan=OFFLINE_MAX)
    grant = connect(browser)
    sessions = offline_sessions("user1")
    record("offline session listed for workspace-backup",
           bool(sessions), f"{len(sessions)} session(s)")
    claims = jwt_claims(grant["refresh_token"])
    record("offline token exp with 180-day maximum (informational)", True,
           f"exp-iat {claims.get('exp', 0) - claims.get('iat', 0)}s, "
           f"refresh_expires_in {grant.get('refresh_expires_in')}")


def check_introspection(login: dict[str, Any],
                        backup: dict[str, Any]) -> None:
    """login-relay's confidential client introspects backup tokens."""
    answer = introspect(backup["access_token"])
    save("introspect-workspace-backup-access-without-audience", answer)
    record("backup token without dtaas-workspace in aud is inactive",
           answer.json() == {"active": False},
           f"aud {jwt_claims(backup['access_token']).get('aud')}")
    add_audience("workspace-backup", "dtaas-workspace")
    backup = refresh(backup["refresh_token"]).json()
    answer = introspect(backup["access_token"])
    save("introspect-workspace-backup-access", answer)
    body = answer.json()
    record("with the audience mapper: dtaas-workspace introspects it",
           body.get("active") is True
           and body.get("azp") == "workspace-backup"
           and body.get("username") == "user1",
           f"client_id {body.get('client_id')}, azp {body.get('azp')}, "
           f"username {body.get('username')}, fields {sorted(body)}")
    answer = introspect(login["access_token"])
    save("introspect-dtaas-workspace-access", answer)
    body = answer.json()
    record("introspection of the login token",
           body.get("active") is True and body.get("username") == "user1",
           f"client_id {body.get('client_id')}, aud {body.get('aud')}")
    answer = introspect(backup["refresh_token"])
    save("introspect-workspace-backup-offline", answer)
    record("introspection of the offline token (informational)", True,
           f"active {answer.json().get('active')}, "
           f"typ {answer.json().get('typ')}")
    answer = introspect(backup["access_token"], client="workspace-backup")
    save("introspect-by-public-client", answer)
    record("public client cannot introspect",
           answer.status_code in (400, 401)
           or answer.json().get("active") is not True,
           oauth_error(answer))
    answer = introspect(backup["access_token"], secret="wrong")
    record("introspection with a wrong secret refused",
           answer.status_code == 401, oauth_error(answer))
    answer = introspect("not-a-token")
    save("introspect-unknown-token", answer)
    record("unknown token is inactive", answer.json() == {"active": False},
           answer.text[:60])


def check_consent_denied() -> None:
    """Declining offline access returns error=access_denied."""
    browser = Browser("user2")
    params = auth_params(pkce_pair()[1], user="user2")
    got, consent = get_code(browser, params, accept=False)
    record("declining consent returns access_denied",
           consent and got.get("error") == "access_denied",
           f"{got.get('error')}")


def check_revocation(browser: Browser) -> None:
    """Disconnect, user disabled, offline sessions revoked by an admin."""
    grant = connect(browser)
    answer = requests.post(f"{OIDC}/revoke", data={
        "token": grant["refresh_token"], "token_type_hint": "refresh_token",
        "client_id": "workspace-backup"}, timeout=TIMEOUT)
    save("revoke-public-offline-token", answer)
    after = refresh(grant["refresh_token"])
    record("public revoke of the offline token",
           answer.status_code == 200 and after.status_code == 400,
           f"revoke HTTP {answer.status_code}, refresh {oauth_error(after)}")
    record("revoke ends the offline session (informational)", True,
           f"{len(offline_sessions('user1'))} offline session(s) left")

    user2 = Browser("user2")
    grant = connect(user2)
    uid = user_uuid("user2")
    api("PUT", f"/users/{uid}", json={"enabled": False}).raise_for_status()
    try:
        answer = refresh(grant["refresh_token"])
        save("token-refresh-disabled-user", answer)
        record("disabled user's refresh refused", answer.status_code == 400,
               oauth_error(answer))
        body = introspect(grant["access_token"]).json()
        record("disabled user's access token inactive (informational)", True,
               f"active {body.get('active')}")
    finally:
        api("PUT", f"/users/{uid}", json={"enabled": True})

    grant = connect(user2)
    api("DELETE", f"/users/{uid}/consents/workspace-backup")
    answer = refresh(grant["refresh_token"])
    save("token-refresh-consent-revoked", answer)
    record("admin revoking the consent ends the offline grant",
           answer.status_code == 400, oauth_error(answer))


def main() -> int:
    """Run every check, write the summary, return non-zero on a failure."""
    info = requests.get(f"{INTERNAL}/admin/serverinfo", headers={
        "Authorization": f"Bearer {admin_token()}"}, timeout=TIMEOUT)
    record("Keycloak version", True,
           info.json().get("systemInfo", {}).get("version", "?"))
    setup_realm()
    check_backchannel()
    browser = Browser("user1")
    check_login_client(browser)
    browser.signed_in = False
    check_pkce(browser)
    record("workspace-backup authorize reused the DTaaS SSO session",
           not browser.signed_in)
    check_redirect_uris(browser)
    check_introspection(check_login_client(browser), connect(browser))
    check_offline_grant(browser)
    check_offline_maximum(browser)
    check_consent_denied()
    check_revocation(browser)
    return finish(f"s4-keycloak-{info.json()['systemInfo']['version']}")


if __name__ == "__main__":
    sys.exit(main())
