# Workspace storage backup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task.
> Tasks are in [tasks](../tasks/102-s3-backup.md) and use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** Back up workspace assets to git or S3 with logins through
login-relay, and move four DTaaS deployments from
`traefik-forward-auth` to Oathkeeper and login-relay.

**Architecture:** workspace-admin gains a backend-neutral scheduler,
an S3 backend driving `rclone`, a login core that owns connections and
asks login-relay for session checks and storage passes, an asset
configuration package, and two clients (a page behind nginx and a CLI
on a Unix socket). login-relay gains GitLab and Keycloak profiles, an
introspection adapter, a token exchange and a callback bounce. The
[roadmap](../FEATURE_ROADMAP.md) lists every pull request in build
order with its dependencies.

**Tech Stack:** Python 3.12, FastAPI, uvicorn, standard-library HTTP,
XML and locking in workspace-admin; `authlib` and `httpx` in
login-relay (existing); `rclone`; SeaweedFS 4.40+; Oathkeeper;
Keycloak; GitLab; nginx; Docker Compose.

**Spec:** [specs/102-s3-backup.md](../specs/102-s3-backup.md); design in
[design/storage](../design/storage/README.md),
[design/workspace-admin](../design/workspace-admin/README.md) and
[LOGIN_RELAY](../design/auth/LOGIN_RELAY.md).

## Global Constraints

- workspace-admin: Python `^3.12`, no new runtime dependency.
- login-relay: no new dependency beyond its `requirements.txt`.
- `rclone` and SeaweedFS (`>= 4.40`) pinned to the latest stable
  release at spike time, with checksums: rclone v1.75.2, SeaweedFS
  4.48 ([spike findings](../tasks/102-s3-backup.md#spike-findings)).
  Keycloak checked at spike time: 26.8.1 and 26.7.4 (S4).
- Asset names `^[a-z0-9]{1,63}$`, defined once in `admin/assets`.
- Secret and config files: mode `0600`, temp file, `fsync`, rename.
- Admin TCP listener `127.0.0.1`; control socket in
  `/tmp/workspace-admin-<uid>/` (mode `0700`).
- OAuth: PKCE S256; `state` is `<user>.<random>`, single use,
  10 minutes; one bounce URI per provider.
- Storage pass 5 minutes; STS `S3_SESSION_SECONDS` 3600;
  `S3_MAX_DELETE` 1000; `NONCURRENT_VERSION_DAYS` 365;
  `CONNECTION_MAX_AGE_DAYS` 180; Oathkeeper and session caches
  30 seconds.
- Shutdown within 8 seconds.
- New files under 250 lines; functions under 25; files already over
  250 lines do not grow; pylint `--fail-under=9.0`; coverage not below
  the baselines recorded in F1 and F3.
- Every pull request updates the docs it makes stale (admin
  `README.md`, `DOCUMENTATION.md`, repository `CLAUDE.md`,
  `docs/CHANGELOG.md`, login-relay `MOTIVATION.md`).
- Test commands:

  ```bash
  # workspaces/src/admin
  poetry run pylint src/admin tests --rcfile=../../../.pylintrc --fail-under=9.0
  poetry run pytest --cov=admin
  # workspaces/test/dtaas/login-relay (pytest-cov added to requirements-dev.txt in F3)
  pytest --cov=. --tb=short
  ```

## Review Focus

1. **Hand edit during a page save.** Expect `config_changed` and no
   write. Test: `test_writer_refuses_changed_file` (F1).
2. **Crash between receiving and saving a rotated refresh token.**
   Expect the old file intact, never half-written; if the provider has
   already revoked the old token, status `login_expired` and Reconnect.
   Tests: `test_store_save_is_atomic` (F2),
   `test_lost_rotation_is_login_expired` (F5).
3. **Unmounted or emptied asset folder.** Expect no `rclone` call and
   `s3_empty_source`. Test: `test_sync_refuses_empty_tree` (F2).
4. **login-relay or the provider down while git assets exist.** Expect
   git assets to sync and S3 assets to report `login_unreachable`.
   Test: `test_round_isolates_connection_failure` (F5).
5. **GitLab token valid but user removed from `WORKSPACE_USERS`.**
   Expect introspection `active: false` and exchange refusal. Tests:
   `test_unlisted_user_inactive`, `test_exchange_refuses_unlisted_user`
   (F3, F4).

## File structure

Admin paths below `workspaces/src/admin/src/admin/`; login-relay paths
below `workspaces/test/dtaas/login-relay/`.

| Feature | Create | Modify |
| :--- | :--- | :--- |
| F1 | `backup/{__init__,base,errors,status,scheduler}.py`, `git/backend.py`, `assets/{__init__,model,loader,writer}.py`, `wiring.py` | `main.py`, `api.py`, `git/*.py` imports, `workspaces/src/startup/custom_startup.sh`, test compose `cap_drop` |
| F2 | `s3/{__init__,settings,runner,errors,backend}.py`, `shared.py`, `login/{__init__,store}.py` | `wiring.py`, `workspaces/Dockerfile.ubuntu.noble.xfce`, test compose files |
| F3 | `profiles/{__init__,base,keycloak,gitlab}.py`, `tests/fakes/gitlab.py`, `tests/contract/` | `main.py`, `_config.py`, `_helpers.py` (shrinks), `requirements-dev.txt`, `workspaces/test/dtaas/oathkeeper/oathkeeper.yml` |
| F4 | `exchange.py`, `bounce.py` | `main.py`, `_config.py`, test compose (signing key secret) |
| F5 | `login/{httpclient,providers,pkce,pending,flow,owner,relay,credentials,session,sts,errors}.py`, `web/{__init__,callbacks,auth,control}.py`, `server.py` | `main.py`, `backup/status.py`, `workspaces/src/startup/nginx.conf` |
| F6 | `cli/{__init__,client,commands}.py` | `main.py` |
| F7 | — | `login/providers.py`, `login/owner.py`, `git/{auth,backend}.py`, `assets/loader.py` |
| F8 | `web/{config_routes,csrf,headers}.py`, `web/static/{index.html,app.js}` | `server.py`, `nginx.conf` |
| F9 | — | DTaaS: compose and docs of the four deployments |
| F10 | DTaaS: `<deployment>/storage/{provision.sh,iam.json.tmpl}` | DTaaS: compose, docs, `mkdocs.yml`, `mkdocs-github.yml` |

## Interfaces between features

```python
# admin: backup/ (F1)
class BackupErrorKind(StrEnum): ...   # SyncErrorKind moved and renamed + new kinds
BackendKind = Literal["git", "s3"]
class Backend(Protocol):
    name: str; kind: BackendKind
    def prepare(self, stop_event: threading.Event) -> None: ...
    def sync(self, stop_event: threading.Event) -> None: ...     # raises BackupError
class BackupStatus:
    def set_assets(self, kinds: dict[str, BackendKind]) -> None: ...
    def record_success(self, name: str) -> None: ...
    def record_failure(self, name: str, kind: BackupErrorKind) -> None: ...
    def set_connection(self, provider: ProviderName, state: ConnectionState) -> None: ...  # F5
    def snapshot(self) -> dict[str, Any]: ...
def start_scheduler(build: Callable[[], list[Backend]], interval: int,
                    stop_event: threading.Event, status: BackupStatus,
                    round_hook: Callable[[list[Backend]], None] | None = None) -> Scheduler: ...

# admin: assets/ and wiring (F1)
@dataclass(frozen=True)
class GitSettings:
    url: str; branch: str
    auth: Literal["token", "gitlab"] = "token"
    token: str | None = field(default=None, repr=False)
@dataclass(frozen=True)
class AssetConfig:
    name: str; backend: BackendKind; git: GitSettings | None = None
@dataclass(frozen=True)
class ConfigSnapshot:
    path: Path; assets: tuple[AssetConfig, ...]; interval: int; digest: str
def read_snapshot(path: Path) -> ConfigSnapshot: ...
def add_asset(snapshot: ConfigSnapshot, asset: AssetConfig) -> ConfigSnapshot: ...   # ConfigChanged
def remove_asset(snapshot: ConfigSnapshot, name: str) -> ConfigSnapshot: ...
def build_backends(snapshot: ConfigSnapshot, status: BackupStatus) -> list[Backend]: ...

# admin: shared.py (F2), imported by backup and login
ProviderName = Literal["gitlab", "keycloak", "s3keys"]
OAuthProvider = Literal["gitlab", "keycloak"]
ConnectionState = Literal["connected", "not_connected", "expired"]   # expired = kind login_expired

# admin: login/ (F2 store, F5 rest)
@dataclass(frozen=True)
class Connection:
    provider: ProviderName; subject: str; obtained_at: datetime
    secret: dict[str, str] = field(repr=False)
def start(provider: OAuthProvider, username: str, poll_id: str | None = None) -> str: ...
def complete(provider: OAuthProvider, code: str, state: str, username: str) -> Connection: ...
def verify(access_token: str) -> str: ...            # via relay.introspect; SessionError
def s3_credentials() -> S3Credentials: ...           # refresh -> exchange -> STS
def gitlab_access_token() -> str: ...                # F7

# login-relay (F3, F4)
class Profile(Protocol):
    def authorize_url(self, state: str, challenge: str) -> str: ...
    async def redeem(self, code: str, verifier: str) -> Tokens: ...
    async def validate_id_token(self, id_token: str) -> None: ...
    async def introspect(self, token: str) -> Introspection: ...   # live check
    async def revoke(self, token: str) -> None: ...
    def logout_url(self) -> str: ...
@dataclass(frozen=True)
class Introspection:
    active: bool; username: str = ""; sub: str = ""; client_id: str = ""
    scope: str = ""; exp: int = 0; groups: tuple[str, ...] = ()
async def exchange(subject_token: str) -> str: ...   # signed ES256 JWT, 5 minutes
def bounce_target(provider: str, code: str, state: str) -> str: ...   # ValueError if unlisted
```

The introspection JSON contract is defined once, in
[LOGIN_RELAY](../design/auth/LOGIN_RELAY.md#api); login-relay's
`Introspection` produces it and the admin's `relay.py` parses it.
`exchange` requires `client_id == BACKUP_CLIENT_ID`. `wiring.py` builds
the round hook, which calls the login core and hands credentials to
the backends, so `admin/backup` never imports `admin/login`.

## Testing strategy

| Level | Scope | Tooling |
| :--- | :--- | :--- |
| Unit | Every module of both services | pytest; fakes on `PATH` or `http.server` |
| Contract | `/storage/status` byte-identity; login-relay's RFC 7662 answers | Snapshot tests written before the change |
| Integration | S3 round trip, versions, restore, deletion brake | SeaweedFS container (F2) |
| Integration | Keycloak profile, exchange, STS trust, isolation, revocation | login-relay, Keycloak, SeaweedFS containers (F4, F5) |
| Integration | GitLab profile | login-relay against `tests/fakes/gitlab.py` (also a service in the CI compose); contract tests replaying GitLab responses recorded in spike S3; a manual check against a real GitLab per release (F3, F7) |
| Browser | Login, page flows, CSRF, headers, expired session | Playwright against the test compose (F8) |
| Compose | Front door, `NET_RAW`, internal-only endpoints | `test-compositions.yml` (F1, F2, F4, F5, F9) |

## Risks

| Risk | Mitigation |
| :--- | :--- |
| SeaweedFS STS with an external issuer, policy variables or lifecycle differ from its wiki | Spike S1 confirmed all three on 4.48; lifecycle runs only from the daily `seaweedfs-lifecycle` pass |
| GitLab rate limits on introspection | 30-second Oathkeeper cache; 2-hour tokens |
| login-relay becomes a single point of failure for logins, sessions and backups | Healthcheck and restart policy; backups retry next round |
| Signing-key leak | Docker secret; rotation with overlapping keys; never in workspaces |
| Migration of four deployments breaks logins | One deployment per PR in F9; rollback by restoring the forward-auth compose |
| Comments lost when the writer rewrites a hand-edited file | Warning before the first save |
