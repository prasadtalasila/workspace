# Decision record: Route B and storage

Part of the [storage design](README.md). **Status: accepted.** Route B
([LOGIN_RELAY](../auth/LOGIN_RELAY.md)) puts `login-relay` and
Oathkeeper in four deployments, with **GitLab** as the identity
provider in three of them and **Keycloak** in one. This record keeps
the facts and reasoning behind that choice. The other storage documents,
[STORAGE_GITLAB](STORAGE_GITLAB.md) and
[STORAGE_KEYCLOAK](STORAGE_KEYCLOAK.md) describe the resulting design.

## What stays the same

Assets and their names; `config.toml`; the writer and live reload;
the S3 backend and `rclone`; git backup; the `/config` page and CLI;
the control socket; status reporting; storage-side hardening; most of
the threat model.

## Facts that drive the changes

| Fact about GitLab | Source | Consequence |
| :--- | :--- | :--- |
| Access tokens are opaque | GitLab OAuth docs | Neither Oathkeeper nor STS can verify them alone |
| `/oauth/introspect` answers only for the caller's own application and names no user | Spike S3 (GitLab 19.5.1) | `login-relay` adapts `/oauth/token/info` and `/oauth/userinfo` |
| Refresh responses are documented without an ID token, yet 19.5.1 returns one | GitLab OAuth API docs; issue #44485; spike S3 | A background job cannot rely on a fresh ID token |
| ID tokens hold few claims (`sub`; username via `userinfo`) and live 2 minutes | GitLab OIDC provider docs; issues #388176, #377654 | No `${jwt:nickname}` policy variable to rely on |
| Refresh tokens have no fixed expiry | GitLab OAuth docs | The 180-day grant maximum cannot be enforced in GitLab |

Spike task S3 checked them on GitLab 19.5.1
([findings](../../tasks/102-s3-backup.md#s3-gitlab)).

## Effects and decisions

### E1. Two identity profiles

The deployment's identity provider is Keycloak or GitLab. Storage stops
saying "Keycloak for S3": **S3 uses the deployment's identity
provider**, and git always uses GitLab. A deployment-wide
`IDENTITY_PROVIDER = keycloak | gitlab` selects the profile.

### E2. Session verification through login-relay

The admin verifies browser sessions, for `/config` and for the nginx
front door, by calling `login-relay`'s internal `/token/introspect`
instead of Keycloak `userinfo`. `login-relay` already answers
inactive for tokens of other clients or unlisted users; the admin
requires `active` and `username == MAIN_USER`. One
code path serves both profiles, and the front door and page work in
all four deployments. Residual risk 5 in
the [threat model](THREAT_MODEL.md#residual-risks) disappears once F9
lands. The 30-second cache stays.

### E3. S3 credentials: login-relay as token bridge

STS needs a verifiable JWT carrying the username. GitLab cannot supply
one in the background (opaque access tokens; ID tokens that live 2
minutes and are documented as absent on refresh).
Options:

| Option | Central revocation | Per-user secrets | Verdict |
| :--- | :--- | :--- | :--- |
| **Token bridge**: `login-relay` exchanges a provider access token for its own short JWT | Yes | None | **Chosen** |
| Per-user static S3 keys from provisioning | No | One per user | Fallback only |
| Keycloak just for storage | Yes | None | Contradicts Route B |

The bridge, an internal endpoint of `login-relay`:

```text
POST /token/exchange   (internal only, never routed by Traefik)
  subject_token=<provider access token>
  1. validate the token live: Keycloak introspection, or GitLab
     /oauth/token/info + /oauth/userinfo
  2. require client = workspace-backup, username in WORKSPACE_USERS
  3. return a JWT: iss=<login-relay issuer>, aud=workspace-backup,
     preferred_username=<username>, exp = now + 5 minutes,
     signed with login-relay's key (JWKS at /.well-known/jwks.json)
```

SeaweedFS's IAM file then trusts **one** issuer, `login-relay`, in
both profiles. The policy keeps `${jwt:preferred_username}`. Each round
becomes: refresh the provider grant, exchange it at `login-relay`, and
exchange the JWT at STS. The [credentials sequence](CONNECT_BACKENDS.md#credentials-per-round)
gains one hop.

Using the bridge in the Keycloak profile too is a choice. It costs one
extra hop but keeps a single STS trust setup and a single code path,
so it was chosen.

Consequences:

- `login-relay` holds a signing key, a high-value secret. It is
  generated at deployment, stored as a Docker secret, rotated with
  overlapping keys in the JWKS, and never given to workspaces.
- Removing a user from `WORKSPACE_USERS` stops their S3 backups at the
  next round, even with `gitlab.com` as the provider. That gives
  operators a central switch that GitLab alone lacks.
- `OIDC_STS_TOKEN` and the follow-up "GitLab as STS issuer" are dropped.
- For cloud S3, AWS must reach `login-relay`'s JWKS publicly over HTTPS
  (cloud guide, a follow-up).

### E4. Connections in the GitLab profile

The user's GitLab grant serves both S3 (through the bridge) and git,
so the GitLab profile has **one connection, `gitlab`**, with scopes
`openid write_repository`. One click connects everything.

| Profile | Connections | Clicks for S3 and git |
| :--- | :--- | :--- |
| `keycloak` | `keycloak` (S3), `gitlab` (git) | 2 |
| `gitlab` | `gitlab` (S3 and git) | 1 |

The trade-off: a user who only backs up to S3 still grants
`write_repository`. Requesting it only when a git asset exists would
need a second, narrower grant. The single grant was chosen.

### E5. Grant lifetime

GitLab refresh tokens never expire on their own, so the 180-day
maximum moves into the admin. `CONNECTION_MAX_AGE_DAYS` (default 180)
makes a connection older than that report `login_expired` and prompt a
reconnect. In the Keycloak profile, the realm's "Offline Session Max"
is set to the same value.

### E6. Revocation

| Profile | Per-user switches |
| :--- | :--- |
| `keycloak` | Disable the user; revoke offline sessions; remove from `WORKSPACE_USERS` |
| `gitlab` | Remove from `WORKSPACE_USERS` (bridge refuses); block in GitLab; the user revokes the application |

### E7. One redirect URI for all users

With GitLab applications on `gitlab.com` or a university GitLab, the
operator may not be able to provision redirect URIs through an API.
Adding a URI for every new user becomes a manual step.

**Decision:** a callback bounce in `login-relay`. Both providers get
one URI, `https://<server>/login-relay/oauth/<provider>/callback`.
The admin puts the user into `state` (`<user>.<random>`). `login-relay`
checks the user against `WORKSPACE_USERS` and redirects the browser to
`/<user>/config/callback/<provider>?code&state`. `login-relay` never
redeems the code. The admin redeems it with the bounce URI as
`redirect_uri`, still under PKCE and the existing `state` and session
checks. This is decision D14 and removes the per-user step from
provisioning in both profiles.

### E8. Addresses

| Provider | Browser | Containers |
| :--- | :--- | :--- |
| Keycloak | Public URL | `http://keycloak:8080/auth` via `KC_HOSTNAME_BACKCHANNEL_DYNAMIC` |
| External GitLab | Public URL | Public URL; needs outbound internet |
| Integrated GitLab | Public URL | `GITLAB_INTERNAL_URL=http://gitlab/gitlab` |

The admin's git remotes for the integrated GitLab use the internal URL
for the same reason.

### E9. Settings

| Change | Setting |
| :--- | :--- |
| New | `IDENTITY_PROVIDER`, `LOGIN_RELAY_INTERNAL_URL`, `CONNECTION_MAX_AGE_DAYS`, `GITLAB_INTERNAL_URL` |
| Changed | `OIDC_ISSUER` and `OIDC_INTERNAL_URL` apply to the Keycloak profile only; STS trusts `login-relay` |
| Removed | `OIDC_STS_TOKEN`, `OIDC_USERNAME_CLAIM`, `DTAAS_LOGIN_CLIENT_ID` (the check moves into `login-relay`) |

### E10. Threat model

- **New asset:** `login-relay`'s signing key. Whoever holds it can mint
  S3 access for any listed user. Same trust level as `login-relay`'s
  existing role as the login gateway.
- **New boundary:** `/token/exchange` and `/token/introspect` must stay
  unreachable from Traefik. A compose test checks this.
- **Front door:** universal after F9 (E2).
- **Bridge input:** an attacker inside the network can call
  `/token/exchange` with their own token and gets only their own
  prefix, as today with STS.

## Decisions taken

| Question | Answer |
| :--- | :--- |
| Route A (Keycloak everywhere) or Route B | Route B: GitLab deployments use GitLab directly |
| Storage pass from login-relay in the Keycloak deployment too | Yes |
| One GitLab grant for S3 and git | Yes |
| Bounce callback or per-user redirect URIs | Bounce |
| Grant maximum | 180 days |
| Version retention | Configurable, default 365 days |
| Versions of SeaweedFS, rclone, Keycloak, GitLab | Latest stable, pinned by the spike: SeaweedFS 4.48 (S1), rclone v1.75.2 (S2), GitLab 19.5.1 (S3), Keycloak 26.8.1 (S4) |

The build order is in the [feature roadmap](../../FEATURE_ROADMAP.md):
login-relay work is F3, F4 and F9.
