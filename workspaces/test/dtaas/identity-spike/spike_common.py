"""Helpers shared by the S3 (GitLab) and S4 (Keycloak) spike checks.

Check results, PKCE, unverified JWT decoding, HTML form scraping for the
providers' sign-in and consent pages, and recording redacted provider
responses for login-relay's contract tests.
"""

# requests is installed only in the spike image.
# pylint: disable=import-error

from __future__ import annotations

import base64
import hashlib
import html.parser
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

OUT = Path(os.environ.get("SPIKE_OUT", "/spike-out"))
RESULTS: list[dict[str, Any]] = []
TIMEOUT = 30


def record(name: str, ok: bool, detail: str = "") -> bool:
    """Print and keep one check result; return ``ok``."""
    RESULTS.append({"check": name, "ok": ok, "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)
    return ok


def finish(phase: str) -> int:
    """Write the results file and return the exit status."""
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"results-{phase}.json").write_text(json.dumps(RESULTS, indent=1))
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    for result in failed:
        print(f"FAILED  {result['check']}  {result['detail']}")
    return 1 if failed else 0


def oauth_error(answer: requests.Response) -> str:
    """Return ``HTTP <status> <error>: <description>``, never a token."""
    try:
        body = answer.json()
    except ValueError:
        return f"HTTP {answer.status_code}"
    if not isinstance(body, dict) or "error" not in body:
        return f"HTTP {answer.status_code}"
    detail = body.get("error_description")
    return (f"HTTP {answer.status_code} {body['error']}"
            + (f": {detail}" if detail else ""))


def pkce_pair() -> tuple[str, str]:
    """Return a PKCE verifier and its S256 challenge."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def jwt_claims(token: str) -> dict[str, Any]:
    """Decode a JWT's payload without checking it."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def jwt_header(token: str) -> dict[str, Any]:
    """Decode a JWT's header without checking it."""
    header = token.split(".")[0]
    header += "=" * (-len(header) % 4)
    return json.loads(base64.urlsafe_b64decode(header))


def query(url: str) -> dict[str, str]:
    """Return the query parameters of ``url`` as single values."""
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


class _FormParser(html.parser.HTMLParser):
    """Collects every form with its action, method and input values."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str,
                        attrs: list[tuple[str, str | None]]) -> None:
        values = {k: v or "" for k, v in attrs}
        if tag == "form":
            self._form = {"action": values.get("action", ""),
                          "method": values.get("method", "get").lower(),
                          "id": values.get("id", ""), "fields": {},
                          "buttons": []}
            self.forms.append(self._form)
        elif self._form is not None and tag in ("input", "button"):
            name = values.get("name")
            kind = values.get("type", "submit" if tag == "button" else "text")
            if kind == "submit":
                self._form["buttons"].append((name, values.get("value", "")))
            elif name:
                self._form["fields"][name] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def forms(page: requests.Response) -> list[dict[str, Any]]:
    """Return the forms of an HTML page, actions made absolute."""
    parser = _FormParser()
    parser.feed(page.text)
    for form in parser.forms:
        form["action"] = urljoin(page.url, form["action"])
    return parser.forms


def find_form(page: requests.Response, pattern: str) -> dict[str, Any]:
    """Return the first form whose action matches ``pattern``."""
    for form in forms(page):
        if re.search(pattern, form["action"]):
            return form
    raise LookupError(f"no form matching {pattern!r} on {page.url} "
                      f"(HTTP {page.status_code})")


# --- Recorded responses -----------------------------------------------------

SECRET_KEYS = {"access_token", "refresh_token", "id_token", "token",
               "code", "secret", "client_secret", "session_state", "sid",
               "jti", "nonce", "at_hash", "c_hash", "x5c", "n", "e", "x",
               "y", "kid", "state", "code_verifier", "code_challenge"}


def redact(value: Any, keep: frozenset[str] = frozenset()) -> Any:
    """Replace secret values with a placeholder naming their kind."""
    if isinstance(value, dict):
        return {k: (f"<{k}>" if k in SECRET_KEYS - keep
                    and isinstance(v, str) else redact(v, keep))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, keep) for v in value]
    return value


def save(name: str, response: requests.Response | dict[str, Any],
         **extra: Any) -> None:
    """Record a provider answer (status and redacted body) for replay."""
    if isinstance(response, requests.Response):
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text[:400]
        entry = {"request": f"{response.request.method} "
                            f"{urlsplit(response.url).path}",
                 "status": response.status_code,
                 "content_type": response.headers.get("Content-Type", ""),
                 "body": redact(body)}
    else:
        entry = {"body": redact(response)}
    entry.update(extra)
    folder = OUT / "recorded"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.json").write_text(
        json.dumps(entry, indent=2, sort_keys=True) + "\n")
