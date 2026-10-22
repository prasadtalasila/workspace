#!/bin/bash
# Seeds the spike GitLab: a root token, users user1 and user2, project
# user1/thesis, and the two applications of STORAGE_GITLAB.md. Writes
# ids and secrets to $STATE (default ./state.json, not committed).
set -euo pipefail

readonly BASE="http://localhost:8929"
readonly STATE="${STATE:-./state.json}"
readonly PW="Hn3sWq8zTf6cYb1D"

# /-/readiness answers 404 outside its allowlist, so wait for the page.
until curl -fsS "${BASE}/users/sign_in" >/dev/null 2>&1; do sleep 10; done

root_token="$(docker compose -f compose.yml exec -T gitlab gitlab-rails runner '
  u = User.find_by_username("root")
  attrs = { name: "spike", scopes: [:api, :sudo], expires_at: 7.days.from_now }
  if PersonalAccessToken.column_names.include?("organization_id")
    attrs[:organization] = Organizations::Organization.first
  end
  puts u.personal_access_tokens.create!(attrs).token' | tail -1)"

api() {
  curl -fsS -H "PRIVATE-TOKEN: ${root_token}" "$@"
}

user_id() {
  api -X POST "${BASE}/api/v4/users" \
    -d "username=$1" -d "name=$1" -d "email=$1@example.org" \
    -d "password=${PW}" -d skip_confirmation=true | jq -r .id
}
uid1="$(user_id user1)"
uid2="$(user_id user2)"

# Passwords set by an administrator expire at once; the spike signs in
# with them, so clear the expiry.
docker compose -f compose.yml exec -T gitlab gitlab-rails runner '
  User.where(username: %w[user1 user2]).update_all(password_expires_at: nil)'

api -X POST "${BASE}/api/v4/projects/user/${uid1}" \
  -d name=thesis -d initialize_with_readme=true >/dev/null

login_app="$(api -X POST "${BASE}/api/v4/applications" \
  -d name=dtaas-login -d confidential=true -d scopes=openid \
  --data-urlencode 'redirect_uri=https://dtaas.example.org/login-relay/callback')"
backup_app="$(api -X POST "${BASE}/api/v4/applications" \
  -d name=workspace-backup -d confidential=false \
  --data-urlencode 'scopes=openid write_repository' \
  --data-urlencode 'redirect_uri=https://dtaas.example.org/login-relay/oauth/gitlab/callback')"

jq -n --arg root "${root_token}" --arg pw "${PW}" \
  --argjson u1 "${uid1}" --argjson u2 "${uid2}" \
  --argjson login "${login_app}" --argjson backup "${backup_app}" \
  '{root_token: $root, password: $pw, user1_id: $u1, user2_id: $u2,
    login: $login, backup: $backup}' > "${STATE}"
chmod 600 "${STATE}"
echo "seeded; state in ${STATE}"
