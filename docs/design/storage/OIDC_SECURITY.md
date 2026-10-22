# OIDC security

Part of the [storage design](README.md). This document explains the
identity profiles, the tokens, the login flows and how Keycloak and
GitLab differ. Step-by-step examples are in
[LOGIN_RELAY](../auth/LOGIN_RELAY.md),
[STORAGE_GITLAB](STORAGE_GITLAB.md) and
[STORAGE_KEYCLOAK](STORAGE_KEYCLOAK.md); the code is in
[workspace-admin sign-in](../workspace-admin/SIGN_IN.md) and
[login core](../workspace-admin/LOGIN_CORE.md).

## Identity profiles

Each DTaaS deployment has one identity provider. **Deployments that
log in with GitLab use GitLab directly**; only
`workspace/keycloak/production` uses Keycloak.

| | GitLab profile | Keycloak profile |
| :--- | :--- | :--- |
| Deployments | `server`, `secure-server`, `secure-server_with_integrated-gitlab` | `workspace/keycloak/production` |
| Login (login-relay) | GitLab application `dtaas-login` | Keycloak client `dtaas-workspace` |
| S3 connection | GitLab application `workspace-backup` | Keycloak client `workspace-backup` |
| Git connection | Same GitLab grant as S3 | GitLab application `workspace-backup`, when `GITLAB_URL` is set |
| Storage pass | login-relay, from the GitLab token | login-relay, from the Keycloak token |
| Clicks to connect S3 and git | 1 | 2 |

The `workspace-backup` clients are **public** with PKCE (S256): the
workspace image carries no client secret, and PKCE proves that whoever
redeems a code also started the login. SeaweedFS trusts only
login-relay's signing keys in both profiles.

## Tokens

| Token | Issued by | Lifetime | Stored | Used for |
| :--- | :--- | :--- | :--- | :--- |
| `dtaas_access_token` cookie | Provider, via login-relay | 2 hours (GitLab), 5 minutes (Keycloak) | Browser only | Proving the browser session to Oathkeeper, nginx and `/config` |
| GitLab refresh token | GitLab | No fixed expiry; replaced on each use; admin limit 180 days | `tokens/gitlab.json` | Getting GitLab access tokens |
| GitLab access token | GitLab | 2 hours | Memory | Git over HTTPS; input to the storage pass |
| Keycloak offline refresh token | Keycloak | 30 days unused, 180 days at most | `tokens/keycloak.json` | Getting Keycloak access tokens |
| Keycloak access token | Keycloak | 5 minutes | Memory | Input to the storage pass |
| Storage pass | login-relay `/token/exchange` | 5 minutes | Memory | Web identity for STS |
| STS temporary credentials | SeaweedFS or AWS STS | `S3_SESSION_SECONDS`, default 3600; SeaweedFS's `maxSessionLength` caps it at 1 hour | Memory, passed to `rclone` | Signing S3 requests |
| Static S3 key pair | Operator | Until rotated | `tokens/s3keys.json` | S3 services without STS, and tests |
| Pasted git token | User | Host policy; GitLab 365 days by default | `config.toml` | Git over HTTPS |

### Why a refresh token, and why a storage pass

Backups run every few minutes, also when the user is not logged in,
so workspace-admin holds its own long-lived grant. STS needs a signed
token that names the user. GitLab access tokens are opaque and a
GitLab refresh returns no ID token. login-relay therefore checks the
provider's token live and signs a 5-minute pass. It does the same for
Keycloak, so both profiles share one path.

### How long grants live

- **GitLab:** no fixed expiry; ends when revoked, when the user is
  blocked, or after `CONNECTION_MAX_AGE_DAYS` (180), enforced by the
  admin.
- **Keycloak:** "Offline Session Idle" 30 days (never reached while
  the workspace runs, since every round refreshes); "Offline Session
  Max" 180 days.

Both may rotate the refresh token on every refresh. Keycloak returns
a new one each time but keeps the old one valid while the realm's
"Revoke Refresh Token" is off, as it stays (spike S4). The admin saves
the new one before using the access token, by temp file and rename,
under a per-provider lock. An ended grant shows as `login_expired`.

## Login flows

### Browser login with PKCE (primary)

The page, or the CLI over the control socket, starts the login; the
user approves in their own DTaaS browser, not the VNC desktop. The
provider returns to **one shared address** at login-relay,
`https://<server>/login-relay/oauth/<provider>/callback`. login-relay
reads the user from `state` (`<user>.<random>`), checks it against
`WORKSPACE_USERS`, and redirects to
`/<user>/config/callback/<provider>`. workspace-admin redeems the code
there with its PKCE secret. Adding a user never changes the provider
registration.

### Device authorization (follow-up)

Short code, approve in any browser, no callback. Keycloak supports it;
GitLab only in recent releases. Not needed while login-relay runs in
every deployment.

### Flows not used

| Flow | Why not |
| :--- | :--- |
| Loopback redirect to `127.0.0.1` | The user's browser runs outside the container |
| Client credentials | Needs a secret per workspace; the token is not the user's |
| Provider token exchange from the session cookie | Needs a confidential client, so a secret in every workspace |
| login-relay keeps a refresh token at DTaaS login | It would hold every user's grant; every user would be asked for offline access |
| GitLab ID token straight to STS | GitLab returns no ID token on refresh, and ID tokens expire in 2 minutes |
| Password grant | Deprecated; integration tests only |

## Keycloak and GitLab compared

| Aspect | Keycloak | GitLab |
| :--- | :--- | :--- |
| Authorize | `<realm>/protocol/openid-connect/auth` (public URL) | `/oauth/authorize` (public URL) |
| Token, revoke | `/token`, `/revoke` on `http://keycloak:8080` (discovery names the public `/revoke`) | `/oauth/token`, `/oauth/revoke` on `GITLAB_INTERNAL_URL` |
| Checking a token | Standard introspection; login-relay's client must be in the token's `aud` | `/oauth/token/info` + `/oauth/userinfo` (no standard introspection) |
| Scopes for storage | `openid offline_access` | `openid write_repository` |
| Access token | Signed JWT, 5 minutes | Opaque, 2 hours |
| Username | `preferred_username` | `nickname` |
| Redirect URIs | Exact list or trailing wildcard | Exact list only |
| Consent | Only with "Consent required" | Always on first authorisation |
| Logout | End-session endpoint | None for clients; revoke the token |
| Central revocation | Disable user; revoke offline sessions | Block user; user revokes application |
| Public and internal address | `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true` | `GITLAB_INTERNAL_URL` when integrated |

In both, removing a user from `WORKSPACE_USERS` stops logins and
storage passes.

## Owner checks at connect time

| Provider | Check | Reason |
| :--- | :--- | :--- |
| Keycloak | `preferred_username == MAIN_USER`; else refuse, store nothing, name both | Stops someone completing a login with their own account so the owner's files go to the attacker's prefix |
| GitLab | `nickname == MAIN_USER` (`GITLAB_OWNER_CHECK = "username"`, default); with `"confirm"`, the page or CLI shows the account and stores only after confirmation | GitLab and DTaaS usernames are equal in DTaaS deployments; `confirm` covers exceptions |

After a GitLab connect, the git backend checks read access to every
git asset using it (`git ls-remote`) and reports `repo_unreachable` per
asset, keeping the connection. The first sync confirms push rights.
