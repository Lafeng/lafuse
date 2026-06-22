#!/bin/bash
set -euo pipefail

name=""
username=""
user_id=""
expires_at=""
database="d1media"
target_env="local"
execute=0

usage() {
  cat <<'EOF'
Usage:
  ./scripts/create_api_token.sh --name "PicGo" --username admin --user-id 1
  ./scripts/create_api_token.sh --env production --name "PicGo" --username admin --user-id 1 --execute

Options:
  --name NAME        Token name shown in D1.
  --username NAME    Username recorded on uploaded media.
  --user-id ID       User id recorded on uploaded media.
  --expires-at TS    Optional Unix timestamp expiration.
  --env NAME         local or a Wrangler environment name. Default: local.
  --database NAME    D1 database binding/name. Default: d1media.
  --execute          Execute with Wrangler. Without this, only prints SQL.
  -h, --help         Show this help.

The script prints the plaintext token once and prints SQL for api_tokens.
It reads AUTH_SALT from the environment or a hidden prompt.
EOF
}

hash_hmac_sha256() {
  local key="$1"
  local value="$2"
  if command -v openssl >/dev/null 2>&1; then
    printf '%s' "$value" \
      | openssl dgst -sha256 -mac HMAC -macopt "key:$key" -binary \
      | openssl base64 -A \
      | tr '+/' '-_' \
      | tr -d '='
    return
  fi
  echo "Missing openssl" >&2
  return 1
}

random_base64url() {
  local bytes="$1"
  openssl rand -base64 "$bytes" | tr '+/' '-_' | tr -d '=\n'
}

random_token_id() {
  openssl rand -hex 6
}

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      name="${2:-}"
      shift 2
      ;;
    --username)
      username="${2:-}"
      shift 2
      ;;
    --user-id)
      user_id="${2:-}"
      shift 2
      ;;
    --expires-at)
      expires_at="${2:-}"
      shift 2
      ;;
    --env)
      target_env="${2:-}"
      shift 2
      ;;
    --database)
      database="${2:-}"
      shift 2
      ;;
    --execute)
      execute=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$name" ]; then
  read -rp "Token name: " name
fi
if [ -z "$username" ]; then
  read -rp "Username: " username
fi
if [ -z "$user_id" ]; then
  read -rp "User id: " user_id
fi

if [ -z "$name" ] || [ -z "$username" ] || [ -z "$user_id" ]; then
  echo "name, username, and user-id are required" >&2
  exit 1
fi
if ! printf '%s' "$user_id" | grep -Eq '^[0-9]+$'; then
  echo "user-id must be an integer" >&2
  exit 1
fi
if [ -n "$expires_at" ] && ! printf '%s' "$expires_at" | grep -Eq '^[0-9]+$'; then
  echo "expires-at must be a Unix timestamp" >&2
  exit 1
fi

if [ "$execute" -eq 1 ] && [ "$target_env" != "local" ]; then
  echo "About to create remote API token in D1 database '$database' env '$target_env' for '$username'."
  read -rp "Type '$target_env/$username' to continue: " confirm
  if [ "$confirm" != "$target_env/$username" ]; then
    echo "Cancelled" >&2
    exit 1
  fi
fi

salt="${AUTH_SALT:-}"
if [ -z "$salt" ]; then
  read -rsp "AUTH_SALT: " salt
  echo
fi
if [ -z "$salt" ]; then
  echo "AUTH_SALT is required" >&2
  exit 1
fi

id=$(random_token_id)
secret=$(random_base64url 33)
token="lafuse_v1_${id}_${secret}"
token_hash=$(hash_hmac_sha256 "lafuse-api-token:${salt}" "$token")
created_at=$(date +%s)
name_sql=$(sql_escape "$name")
username_sql=$(sql_escape "$username")
expires_sql="NULL"
if [ -n "$expires_at" ]; then
  expires_sql="$expires_at"
fi
unset salt secret

sql=$(cat <<EOF
INSERT INTO api_tokens (id, name, token_hash, user_id, username, scope, created_at, expires_at, revoked_at)
VALUES ('$id', '$name_sql', '$token_hash', $user_id, '$username_sql', 'upload', $created_at, $expires_sql, NULL);
EOF
)

if [ "$execute" -ne 1 ]; then
cat <<EOF

Plaintext token, save it now:
$token

-- D1 SQL
$sql
EOF
  exit 0
fi

tmp_sql=$(mktemp "${TMPDIR:-/tmp}/lafuse-create-token.XXXXXX.sql")
trap 'rm -f "$tmp_sql"' EXIT
chmod 600 "$tmp_sql"
printf "%s\n" "$sql" > "$tmp_sql"

if [ "$target_env" = "local" ]; then
  npx wrangler d1 execute "$database" --local --file "$tmp_sql"
else
  npx wrangler d1 execute "$database" --env "$target_env" --remote --file "$tmp_sql"
fi

cat <<EOF

Plaintext token, save it now:
$token
EOF
