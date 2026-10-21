# Tasks: workspace storage backup

Implements the [plan](../plans/102-s3-backup.md); interfaces named here
are defined there, and the order and dependencies are in the
[roadmap](../FEATURE_ROADMAP.md#planned-work-in-order). Each task is
one reviewable unit with its own tests, ends with the plan's test
commands passing, and updates the docs it makes stale. Step-level,
test-first detail for a feature is written just before it starts.

## Spike

- [x] **S1 SeaweedFS.** Pin the latest stable release `>= 4.40`.
  Confirm: versioning and `rclone copy --s3-version-at` restore;
  `NoncurrentVersionExpiration` on a versioned bucket;
  `AssumeRoleWithWebIdentity` with an ES256 JWT from an external
  issuer (`iss`, `aud`, JWKS URL) as login-relay will issue; a
  `${jwt:preferred_username}` prefix policy with `s3:prefix` denies
  another prefix; the denies and `GetBucketVersioning` allow of the
  threat model; `--s3-no-check-bucket`; role ARN format.
- [x] **S2 rclone.** Pin the latest stable release with
  `--s3-version-at`, the `SeaweedFS` provider, session tokens,
  `--skip-links`, `--s3-no-check-bucket`; record the SHA-256.
- [x] **S3 GitLab.** On the latest stable GitLab: non-confidential
  application with PKCE; exact redirect URIs; `openid` and
  `openid write_repository`; fields of `/oauth/token/info` and
  `/oauth/userinfo`; 2-hour access tokens; refresh rotation; no ID
  token on refresh.
- [x] **S4 Keycloak.** `KC_HOSTNAME_BACKCHANNEL_DYNAMIC` gives
  internal backchannel URLs and the public `iss`; public
  `workspace-backup` client with PKCE, `offline_access` and consent;
  180-day offline maximum; login-relay's confidential client can
  introspect `workspace-backup` tokens.
  *Check*: findings recorded under "Spike findings"; design docs
  updated where they differ.

## F1 Backup foundation (PR 1, PR 2)

- [ ] **T101 Status contract.** `test_status_snapshot_unchanged` for a
  git-only config, before any change; record test count and coverage.
- [ ] **T102 Backend package.** `backup/*` and `git/backend.py`; move
  `SyncErrorKind` into `BackupErrorKind`; update imports. Tests:
  `test_scheduler_runs_each_backend`,
  `test_failure_in_one_backend_does_not_stop_others`,
  `test_stop_event_ends_round`. (PR 1.)
- [ ] **T103 Asset model and loader.** Name rule, `BACKUP_BACKEND`,
  `GIT_AUTH` (default `token`), per-section validation; drop
  `ASSET_NAMES`. Tests: `test_private_common_configs_unchanged`,
  `test_name_rejected[Private|my-asset|a.b|""|64 chars]`,
  `test_invalid_section_skipped_others_run`.
- [ ] **T104 Writer.** `read_snapshot`, `add_asset`, `remove_asset`,
  TOML emitter, atomic `0600`. Tests: `test_writer_refuses_changed_file`,
  `test_written_file_reloads_identically`.
- [ ] **T105 Wiring and live reload.** Tests:
  `test_reload_waits_for_round`, `test_unparseable_edit_keeps_running`.
- [ ] **T106 Loopback bind.** `main.py` default and
  `custom_startup.sh` use `127.0.0.1`. *Check*: port 8091 refuses
  from another container.
- [ ] **T107 Drop NET_RAW** on workspaces in the test compose files
  and `ci/` variants. (PR 2.)

## F2 S3 storage with static keys (PR 3, PR 4)

- [ ] **T201 SeaweedFS in test compose**: `users` network only, no
  ports or labels, `/data` volume, config mounts, healthcheck;
  host refuses, `user1` reaches. (PR 3.) Spike S1 added the
  `seaweedfs` and `seaweedfs-lifecycle` services to
  `compose.traefik.secure.yml` and `compose.traefik.secure.tls.yml`;
  still to do: the `ci/` variants and a compose test.
- [ ] **T202 S3 settings.** Tests: `test_prefix_is_derived`,
  `test_missing_endpoint_reports_not_configured`.
- [ ] **T203 Token store** `shared.py` and `login/store.py`. Tests:
  `test_store_save_is_atomic`, `test_connection_repr_hides_secret`.
- [ ] **T204 rclone runner and errors.** Tests:
  `test_credentials_never_in_argv`, `test_timeout_kills_group`.
  `--delete-before`; exit 7 with `--max-delete threshold reached` is
  `s3_delete_limit` (S2).
- [ ] **T205 S3 backend.** Tests: `test_sync_refuses_empty_tree`,
  `test_excludes_on_every_call`, `test_versioning_off_refused`,
  `test_delete_limit_reported`.
- [ ] **T206 Image and integration.** Pinned `rclone`; round trip
  against SeaweedFS with a static identity. (PR 4.)

## F3 login-relay identity profiles (PR 5)

- [ ] **T301 Profile interface.** Add `pytest-cov` to
  `requirements-dev.txt`; record login-relay's test count and coverage;
  move today's Keycloak code out of `_helpers.py` behind `Profile`.
  Tests: existing tests pass unchanged.
- [ ] **T302 PKCE, nonce, cookies, compatibility.** PKCE S256 and
  `nonce` in the login; no `prompt` unless `LOGIN_PROMPT` is set;
  `Secure` on both cookies only with `TLS=true`; `KEYCLOAK_CLIENT_*`
  accepted as aliases; only the active profile's secret required.
  Tests: `test_authorize_url_has_pkce_and_nonce`,
  `test_redeem_sends_authorize_redirect_uri`,
  `test_cookies_secure_follow_tls`, `test_old_variable_names_work`.
- [ ] **T303 GitLab profile and adapter.** `/oauth/*` endpoints,
  `GITLAB_INTERNAL_URL`, ID-token checks, introspection adapter,
  revoke on logout and the signed-out page; cross-user check uses
  `introspect`. Tests with `tests/fakes/gitlab.py` and contract tests
  replaying spike S3 responses: `test_adapter_answer_matches_contract`,
  `test_unlisted_user_inactive`, `test_foreign_application_inactive`,
  `test_logout_ends_on_signed_out_page`.
- [ ] **T304 Oathkeeper cache.** `cache: {enabled: true, ttl: 30s}`.
  *Check*: compose login works with the Keycloak profile and with the
  GitLab profile against the fake GitLab service; today's Keycloak and
  Dex CI stacks pass unchanged.

## F4 login-relay storage endpoints (PR 6)

- [ ] **T401 Exchange.** `/token/exchange` (RFC 8693 shape), ES256
  signing from `SIGNING_KEY_FILE`, `/.well-known/jwks.json` and
  discovery; a one-shot service in the test compose generates the
  key set. Tests: `test_exchange_issues_5_minute_jwt`,
  `test_exchange_without_key_is_503`, `test_exchange_provider_down_is_502`,
  `test_exchange_refuses_unlisted_user`,
  `test_exchange_refuses_login_client_token`, `test_jwks_lists_two_keys`.
- [ ] **T402 Bounce.** `/login-relay/oauth/<provider>/callback`. Tests:
  `test_bounce_redirects_listed_user`, `test_bounce_refuses_unlisted`,
  `test_bounce_rejects_malformed_state`, `test_bounce_never_redeems`,
  `test_bounce_username_with_dot`, `test_bounce_unknown_provider`,
  `test_bounce_forwards_only_code_state_error` (GitLab accepts extra
  query parameters on the registered address, S3).
- [ ] **T403 Exposure.** *Check*: `/token/*`, `/authz/*`,
  `/.well-known/*` unreachable through Traefik in the test compose.

## F5 Admin login core and front door (PR 7)

- [ ] **T501 HTTP, providers, PKCE, pending.** Tests:
  `test_pkce_rfc7636_vector`, `test_state_carries_username`,
  `test_state_single_use`, `test_state_expires_after_10_minutes`.
- [ ] **T502 Flow and owner check** for GitLab and Keycloak. Tests:
  `test_owner_mismatch_stores_nothing_and_names_both`,
  `test_redirect_uri_is_bounce`.
- [ ] **T503 Relay client and session check.** `relay.py`,
  `session.py`. Tests: `test_inactive_session_denied`,
  `test_other_user_denied`, `test_relay_down_denies`.
- [ ] **T504 Credentials.** Refresh, rotation, exchange, STS, age
  limit. Tests: `test_rotated_token_saved_before_use`,
  `test_exchange_denied_is_s3_auth_failed`,
  `test_old_connection_is_login_expired`,
  `test_lost_rotation_is_login_expired`,
  `test_round_isolates_connection_failure`.
- [ ] **T505 Servers and routes.** TCP on `127.0.0.1`, control socket
  in a `0700` directory, callbacks, `/_auth`, control routes. Tests:
  `test_socket_directory_mode_0700`, `test_shutdown_within_8_seconds`.
- [ ] **T506 Front door.** nginx `auth_request /_auth` except `/ping` and
  today's public read-only routes (`/services`, `/health`,
  `/storage/status`),
  enabled when `LOGIN_RELAY_INTERNAL_URL` is set. *Check*: from another
  workspace, Jupyter and VS Code answer 401.
- [ ] **T507 Integration** with login-relay, Keycloak and SeaweedFS:
  connect, sync, cross-user and `DeleteObjectVersion` denied, removal
  from `WORKSPACE_USERS` stops the next round.

## F6 CLI (PR 8)

- [ ] **T601 Client** over the control socket. Tests:
  `test_service_not_running_message`.
- [ ] **T602 Commands** `asset list|add|remove|allow-delete`,
  `connect`, `disconnect`, `status`; secrets only from stdin. Tests:
  `test_asset_add_offline`, `test_connect_prints_link_and_waits`.

## F7 GitLab connection for git (PR 9)

- [ ] **T701 Git uses the connection** when `GIT_AUTH = "gitlab"`;
  host must be `GITLAB_URL`'s or `GITLAB_INTERNAL_URL`'s, and only the
  latter may be `http` (integrated GitLab, S3); `git ls-remote` after
  connect. Tests:
  `test_gitlab_auth_header`, `test_repo_unreachable_keeps_connection`.
- [ ] **T702 Credentials via environment** (`GIT_CONFIG_COUNT`) for
  every git credential. Tests: `test_no_credential_in_git_argv`,
  `test_token_auth_unchanged`.

## F8 `/config` page (PR 10)

- [ ] **T801 Routes.** Tests: `test_every_route_requires_session`,
  `test_state_has_no_secrets`.
- [ ] **T802 CSRF and headers.** Tests:
  `test_post_without_csrf_denied`, `test_foreign_origin_denied`,
  `test_security_headers_present`.
- [ ] **T803 Static page.** Playwright: connect GitLab, add S3 and git
  assets, allow deletions, remove, disconnect, changed-on-disk
  warning, expired session.

## F9 DTaaS deployments on login-relay (PR 11)

Every deployment in F9 also gets `cap_drop: [NET_RAW]` on workspaces,
a generated signing key set for login-relay, and
`LOGIN_RELAY_INTERNAL_URL`, which turns on the nginx front door once
the workspace image includes F5.

- [ ] **T901 `server`**: Oathkeeper and login-relay, GitLab profile,
  `TLS=false`; documented as test-only.
- [ ] **T902 `secure-server`**: GitLab profile with TLS.
- [ ] **T903 `secure-server_with_integrated-gitlab`**:
  `GITLAB_INTERNAL_URL=http://gitlab/gitlab`; `dtaas-login`
  application created with the bundled GitLab.
- [ ] **T904 `workspace/keycloak/production`**: Keycloak profile,
  `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`.
  *Check* for each: login, own workspace only, logout; DTaaS docs
  updated; rollback documented.

## F10 Storage in DTaaS deployments (PR 12)

- [ ] **T1001 Provisioning job.** Bucket, versioning, lifecycle
  (`NONCURRENT_VERSION_DAYS`, default 365), `iam.json` trusting
  login-relay; Keycloak `workspace-backup` client (bounce
  redirect URI, audience mapper for login-relay's client, S4).
  *Check*: second run changes nothing; adding a user needs no change.
- [ ] **T1002 Integration.** SeaweedFS on `dtaas-users`; storage
  variables on workspaces; `workspace-backup` GitLab application
  registration documented.
- [ ] **T1003 Operator docs and end-to-end.** Enabling, connecting,
  restore runbook, revocation, monitoring, durability, host backups
  holding tokens, the `MAIN_USER` invariant; `mkdocs.yml` and
  `mkdocs-github.yml` together. *Check*: round trip in a throwaway
  stack of each kind; `mkdocs build` passes.

## Spike findings

S1 and S2 ran on 2026-10-18 against the
SeaweedFS service of `workspaces/test/dtaas/compose.traefik.secure.yml`,
with `seaweedfs/spike/` standing in for login-relay (an ES256 key with
`kid`, JWKS at `http://login-relay:8080/.well-known/jwks.json`). 64 of
64 checks passed, plus 4 after a restart, the lifecycle probe through
the `seaweedfs-lifecycle` service, and 7 rclone checks for S2.

S3 and S4 ran on 2026-10-21 with `identity-spike/` (usage in its
[README](../../workspaces/test/dtaas/identity-spike/README.md)), which
registers the applications and clients through the providers' admin
APIs and drives the browser steps over HTTP. S3: 80 of 80 checks
against a throwaway GitLab under `/gitlab`, as integrated GitLab runs,
and the test compose's Oathkeeper. S4: 67 of 67 against the test
compose's Keycloak behind its Traefik, on 26.7.4 and again on 26.8.1.
The providers' answers, tokens redacted, are in
`identity-spike/recorded/` for login-relay's contract tests (T303).

### S1 SeaweedFS

**Pin:** `chrislusf/seaweedfs:4.48`
(`sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d`),
latest stable on 2026-10-18; release archive `linux_amd64.tar.gz`
SHA-256 `4a7d108384d044d95212d1342cdda9533fa55842c1c9b41f606ca3c8a9561124`.

Confirmed as designed:

- Versioning: an overwrite keeps the old version; a delete adds a
  marker and keeps every version. `rclone copy --s3-version-at` with the
  operator's keys restores a prefix exactly as it was.
- `AssumeRoleWithWebIdentity` accepts an ES256 pass from an external
  issuer (`iss`, `aud`, JWKS URL). It refuses a wrong `aud` or `iss`, an
  expired pass, a key not in the JWKS, a tampered signature, `alg:
  none` and HS256.
- The `${jwt:preferred_username}` policy: `user1` reads, writes, deletes
  and lists `user1/` only. It is refused `user2/`, the look-alike
  `user10/`, the prefix `user1` without slash, and a listing without
  prefix. A key with `..` is refused (`InvalidRequest`).
- The denies hold: `DeleteObjectVersion`, `PutBucketVersioning`,
  `PutLifecycleConfiguration`, `DeleteBucketLifecycle`,
  `PutBucketPolicy`, `CreateBucket`, `DeleteBucket` and
  `ListObjectVersions` are refused. `GetBucketVersioning` is allowed.
  `ListBuckets` is allowed but returns no buckets.
- Objects, versioning, lifecycle and an STS session issued before a
  restart all survive it.
- The service is internal: the host gets no answer on 8333, and a
  container on `dtaas-users` reaches it.

Differs from the design (docs updated):

1. **Role ARN.** `arn:seaweed:iam::role/WorkspaceBackup` is refused.
   Use `arn:aws:iam::role/WorkspaceBackup`, the `roleArn` in
   `iam.json`; `arn:aws:iam::<account>:role/WorkspaceBackup` and
   `arn:aws:iam:::role/WorkspaceBackup` also work. The response carries
   no `AssumedRoleUser`.
2. **No `s3.json`.** The operator identity comes from
   `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the container's
   environment. The admin keys are therefore not in a file.
3. **STS needs `jwt.filer_signing.key`.** Without it, or a `signingKey`
   in `iam.json`, STS does not start ("no signing key found"), and the
   filer's IAM gRPC service accepts unauthenticated calls. The compose
   sets `WEED_JWT_FILER_SIGNING_KEY` from `S3_SIGNING_KEY`. The
   healthcheck (`/healthz`) stays green when IAM fails to load, so the
   provisioning test must call STS.
4. **Session length is the caller's choice.** With
   `maxSessionLength` 12h, a stolen 5-minute pass bought keys for 12
   hours. `iam.json` sets `1h`: `DurationSeconds` above 3600 is refused.
5. **Lifecycle needs a scheduler.** `weed server` stores the
   `NoncurrentVersionExpiration` rule but never applies it, and `weed
   mini`'s worker has no lifecycle capability. The compose adds
   `seaweedfs-lifecycle`, which runs `s3.lifecycle.run-shard -shards
   0-15` daily. A probe that ages two versions, as SeaweedFS's own
   `TestLifecycleNoncurrentVersionExpiration` does, saw the old version
   expire and the current one stay. Aged entries are honoured only by
   the walk of a first pass (no cursor yet); later passes replay the
   filer's meta-log from the moment of demotion, which stock SeaweedFS
   keeps forever, so `/data` grows with it. A 365-day expiry in steady
   state cannot be shown in a spike.
6. **Multipart.** rclone uploads large files in parts; the policy also
   allows `s3:AbortMultipartUpload` and `s3:ListMultipartUploadParts`
   on the user's prefix.
7. **`azp` counts as audience.** A pass with another `aud` but `azp`
   `workspace-backup` is accepted. Only login-relay's keys are trusted,
   and it always sets `aud`, so this is noted, not a risk.
8. **JWKS cache.** A pass with an unknown `kid` makes SeaweedFS fetch
   the JWKS again, so a new key signs as soon as it is published. A
   removed key stays trusted until `jwksCacheTTLSeconds` (3600 in
   `iam.json`); a leaked key is cut off at once only by restarting
   SeaweedFS.
9. **`--s3-no-check-bucket`** is not needed by 4.48: rclone without it
   also syncs under the role. Keep it; other S3 servers differ.

### S2 rclone

**Pin:** rclone v1.75.2, latest stable on 2026-10-18; release
`rclone-v1.75.2-linux-amd64.zip` SHA-256
`349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702`
(matches the release's `SHA256SUMS`; the extracted binary is
`ed7ab1f17876bb006c3df3949a3044959671afd9112362dacaa5dd1647735bc1`).
The `rclone/rclone:1.75.2` image holds a different build; install from
the zip.

- Present: `--s3-version-at`, `--s3-no-check-bucket`,
  `--s3-session-token`, `--skip-links`, `--max-delete`, provider
  `SeaweedFS`.
- A remote defined only by `RCLONE_CONFIG_<NAME>_*` variables, session
  token included, syncs with STS keys; no key reaches the command line.
- `--skip-links` leaves symbolic links out silently, even with `-v`.
- **The deletion brake deletes first.** With `--max-delete N`, rclone
  deletes N objects, then stops with exit code 7 and `--max-delete
  threshold reached` in stderr. Under the default `--delete-after`
  the round's uploads are already done by then. The S3 backend must
  pass `--delete-before` so the brake trips before any upload, and
  should map exit 7 with that message to `s3_delete_limit`. The N
  deletions are noncurrent versions, so they can be restored.
- `rclone sync` from an empty folder plans to delete everything, so the
  admin's `s3_empty_source` refusal is required.
- A user's STS keys cannot `--s3-version-at` (`ListObjectVersions` is
  denied); restore stays with the operator, as designed.

### S3 GitLab

**Pin:** `gitlab/gitlab-ce:19.5.1-ce.0`
(`sha256:bb79dc86267c557fd11e7feb0cd9dd506dd02e991ecdd6cae11ca7d7e5d36fc3`),
latest stable on 2026-10-21. Oathkeeper `oryd/oathkeeper:v26.2.0`
(`sha256:467329abde34feefca217b7af76fff59e77fe1795a19376e9d479f33c7c198fc`),
as in the test compose.

Confirmed as designed:

- A non-confidential application redeems with PKCE S256 and no
  secret. Without `code_verifier` it is refused (`invalid_request`),
  with a wrong one too (`invalid_grant`); a code is single use. The
  confidential `dtaas-login` is refused without its secret
  (`401 invalid_client`).
- Redirect URIs are exact: another path, a trailing slash, another
  host, `https` or upper case get GitLab's error page (HTTP 200, "An
  error has occurred"), never a redirect. Redeeming with another
  `redirect_uri` than the authorize request is `invalid_grant`.
- Scopes: the `dtaas-login` token (`openid`) can neither read nor push
  (git 403). The `workspace-backup` token (`openid write_repository`)
  clones and pushes over `GITLAB_INTERNAL_URL` with HTTP Basic
  `oauth2:<token>`, as `admin.git.auth` sends it, and cannot reach
  another user's private project. A scope the application lacks gets
  the error page.
- `/oauth/token/info`: `resource_owner_id`, `scope` and `scopes`
  (lists), `expires_in`, `expires_in_seconds`, `application.uid`,
  `created_at`. `/oauth/userinfo`: `sub` (the `resource_owner_id` as a
  string), `nickname`, `preferred_username`, `name`, `given_name`,
  `groups`, `picture`, `profile`, `sub_legacy`. Both answer 401
  `invalid_token` for an unknown or revoked token.
- Access tokens last 7200 seconds, from a code and from a refresh.
- Refresh rotates: each refresh returns a new refresh token and revokes
  the previous access token; a used refresh token is `invalid_grant`,
  and the newest one still works after such a reuse. A refresh token
  works only with its own application (`401 invalid_client`).
- ID tokens: RS256, keys at `GITLAB_INTERNAL_URL/oauth/discovery/keys`,
  `iss` the public `GITLAB_URL` also when asked at the internal
  address, `aud` the application uid, `nonce` echoed, 120 seconds.
  Discovery at the internal address names the public issuer.
- Consent is asked on the first authorization of each application,
  and again until a token has been issued; "Deny" returns
  `error=access_denied` with `state`.
- Revocation: the public application revokes with `token` and
  `client_id`. Revoking the refresh token also ends its access token,
  and the other way round.
- Blocking a user ends the grant: token/info rejects the access token,
  and the refresh token never works again, also after unblocking.
- Oathkeeper's `.Extra` holds `username`, `client_id` and `scope` from
  the introspection answer, plus the members of `ext` (`groups`);
  `sub` becomes `.Subject`; `active`, `exp` and `token_type` are not
  passed on. The header mutator sets `X-User-Name`, `X-User-Subject`
  and `X-User-Groups`. user1's token on `/user2/` and a
  `workspace-backup` token on `/user1/` both end in the redirect to
  login-relay.

Differs from the design (docs updated):

1. **ID token on refresh.** GitLab 19.5.1 returns an `id_token` on a
   refresh too: fresh `iat`, the original `auth_time`, no `nonce`, 120
   seconds. The storage pass stays: SeaweedFS would otherwise trust
   each GitLab, the token lives 2 minutes, and `WORKSPACE_USERS` could
   not stop a backup.
2. **Introspection exists.** Discovery advertises `/oauth/introspect`
   (RFC 7662). A confidential application sees only its own tokens
   (another application's token is `active: false`); a public one
   needs only `client_id`. The answer has `active`, `client_id`,
   `scope`, `exp`, `iat`, `token_type`, but no user, so login-relay's
   adapter keeps `/oauth/token/info` and `/oauth/userinfo`.
3. **Blocked user: HTTP 500 once.** The refresh for a blocked user
   fails inside GitLab (`NoMethodError` building the refresh's ID
   token) and answers 500 with an HTML page; the refresh token is gone
   and the next attempt is `invalid_grant`. The admin reports the 5xx
   as `login_unreachable` and the next round's `invalid_grant` as
   `login_expired` (T504).
4. **Query strings pass.** `.../oauth/gitlab/callback?next=/x` is
   accepted and the code is sent there with `next` kept. login-relay's
   bounce forwards only `code`, `state`, `error` and
   `error_description` (T402).
5. **PKCE is optional** for non-confidential applications: an
   authorize request without `code_challenge` yields a code redeemable
   without verifier, and `plain` is accepted. A code issued with an
   S256 challenge always needs its verifier, so the protection holds
   as long as workspace-admin always sends S256.
6. **Revoking for a confidential application needs its secret.** With
   `client_id` only, `/oauth/revoke` answers 403 and the token stays
   valid; login-relay's logout sends `client_secret`.
7. **No 302 once consented.** When consent is skipped, GitLab answers
   the authorize request with an HTML "Redirecting" page (HTTP 200)
   instead of a redirect. Browsers follow it; the fake GitLab may
   answer 302.
8. **Integrated GitLab is `http`.** `admin.git.auth` allows only the
   `https` transport, but remotes on `GITLAB_INTERNAL_URL`
   (`http://gitlab/gitlab/...`) are `http`; T701 allows `http` for
   that host only.
9. **No device flow** is advertised (`device_authorization_endpoint`
   absent); the follow-up stays a follow-up.

### S4 Keycloak

**Pin:** `quay.io/keycloak/keycloak:26.8.1`
(`sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244`),
latest stable on 2026-10-21. The test compose's 26.7.4
(`sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`)
gives the same 67 results.

Confirmed as designed:

- With `KC_HOSTNAME=http://dtaas.test/auth` and
  `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`, discovery read at
  `http://keycloak:8080/auth` names the public issuer and
  `authorization_endpoint`, and internal `token_endpoint`,
  `introspection_endpoint`, `jwks_uri` and `userinfo_endpoint`.
  Discovery through Traefik is public throughout. A code from the
  public authorize page redeems at the internal token endpoint; access
  and ID tokens carry the public `iss`, and the ID token verifies
  against the internal JWKS.
- The public `workspace-backup` client with `pkce.code.challenge.method`
  S256 refuses an authorize request without a challenge or with
  `plain` (`invalid_request`, sent to the redirect URI), and a redeem
  without or with a wrong verifier (`invalid_grant`). It redeems and
  refreshes without a secret; a code is single use.
- "Consent required" shows the consent page once, then remembers it;
  "No" returns `error=access_denied`. The DTaaS SSO session means no
  password at connect.
- `openid offline_access` gives an `Offline` refresh token
  (`refresh_expires_in` 2592000: the 30-day idle). The realm keeps
  "Offline Session Max Limited" with 180 days; a 20-second maximum
  ended a grant in use ("Token is not active"), so the limit holds
  however often the grant is refreshed.
- Redirect URIs are exact, query strings included (400 page); redeeming
  with another `redirect_uri` is `invalid_grant`.
- Access tokens last 300 seconds and carry `preferred_username` and
  `azp` for the owner check. Refresh returns an ID token as well.
- Ends of a grant: revoking the offline token at `/revoke` with
  `client_id` only (200) removes the offline session; a disabled user
  is `invalid_grant` ("User disabled"); an admin revoking the consent
  ends the offline session.
- A public client may not introspect (403); a wrong secret is 401; an
  unknown token is `{"active": false}`.

Differs from the design (docs updated):

1. **Introspection needs the audience.** Keycloak answers `active:
   false` to login-relay's client unless the token's `aud` holds
   `dtaas-workspace`, also for login-relay's own tokens (hence the
   Audience mapper in `KEYCLOAK_SETUP.md`). `workspace-backup` needs
   an Audience mapper adding `dtaas-workspace` to its access tokens;
   then the answer is active with `client_id` and `azp`
   `workspace-backup` and `username` `user1`. Backup tokens then name
   login-relay's client in `aud`, so login-relay must keep telling
   sessions from backup tokens by `client_id` (LR-5), never by `aud`.
2. **Revocation stays public.** With backchannel URLs dynamic,
   `revocation_endpoint` (and `end_session_endpoint`) in internal
   discovery still name the public host. workspace-admin builds the
   revoke URL from `OIDC_INTERNAL_URL` instead of taking it from
   discovery.
3. **Rotation is a realm choice.** Keycloak returns a new refresh token
   on every refresh but, by default ("Revoke Refresh Token" off), the
   old one keeps working. With it on, reusing an old token is
   `invalid_grant` and also ends the newer one ("Session doesn't have
   required client"). The realm keeps it off, so a rotation lost in a
   crash does not end the grant.
