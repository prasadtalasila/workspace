# Identity provider spike

Spike tasks S3 (GitLab) and S4 (Keycloak) of the
[storage backup tasks](../../../../docs/tasks/102-s3-backup.md#spike);
the findings are recorded there. Each check script registers the
applications or clients of the storage design through the provider's
admin API, drives the browser steps over HTTP, and prints one line per
check. The providers' answers, tokens redacted, land in the
`spike-identity-out` volume under `recorded/`; the copies in
`recorded/` here feed login-relay's contract tests.

| File | Does |
| :--- | :--- |
| `spike.gitlab.overlay.yml` | Throwaway GitLab under `/gitlab` (browsers `http://gitlab.test/gitlab`, containers `http://gitlab/gitlab`), the test compose's Oathkeeper, and the S3 checks. The spike container answers as login-relay |
| `gitlab_bootstrap.rb` | Seeds GitLab with an admin API token and the users `user1` and `user2` |
| `spike_s3_gitlab.py` | S3: PKCE, redirect URIs, scopes, token lifetimes, refresh, revocation, token-info and userinfo answers, Oathkeeper's `.Extra` |
| `spike.keycloak.overlay.yml` | The test compose's Keycloak and Traefik with `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`, and the S4 checks |
| `spike.env` | `SERVER_DNS=dtaas.test`: the spike container reaches Traefik by that name, as a browser would |
| `spike_s4_keycloak.py` | S4: backchannel URLs and issuer, PKCE, consent, offline access and its maximum, rotation, introspection, revocation |

Both overlays use the fixed network names `dtaas-frontend` and
`dtaas-users`, so do not run them alongside a `dtaas` stack, nor
together. Their own project name keeps `down -v` away from that stack.
Traefik publishes no host port in the S4 overlay. From
`workspaces/test/dtaas`, with `config/.env` filled in:

```bash
# S3: GitLab takes about four minutes to become healthy.
s3="docker compose -p identity-spike -f compose.traefik.secure.yml \
  -f identity-spike/spike.gitlab.overlay.yml --env-file config/.env"
$s3 up -d --wait gitlab oathkeeper
$s3 exec gitlab gitlab-rails runner /spike/gitlab_bootstrap.rb
$s3 run --rm --build --use-aliases spike-gitlab   # 80 checks
$s3 down -v

# S4; SPIKE_KEYCLOAK_VERSION=26.8.1 tries another release.
s4="docker compose -p identity-spike -f compose.traefik.secure.yml \
  -f identity-spike/spike.keycloak.overlay.yml --env-file config/.env \
  --env-file identity-spike/spike.env"
$s4 up -d --wait keycloak traefik
$s4 run --rm --build spike-keycloak               # 67 checks
$s4 down -v
```

A check named "informational" records what the provider did without
judging it. The S4 run changes realm settings briefly (a 20-second
offline maximum, "Revoke Refresh Token" on) and sets them back; it
creates the realm afresh each time.
