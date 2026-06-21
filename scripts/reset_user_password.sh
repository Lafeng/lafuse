#!/bin/bash
set -euo pipefail

database="d1media"
target_env="local"
username=""
execute=0

usage() {
  cat <<'EOF'
Usage:
  ./scripts/reset_user_password.sh --username admin
  ./scripts/reset_user_password.sh --env production --username admin --execute

Options:
  --username NAME      User to update in the users table.
  --env NAME          local or a Wrangler environment name. Default: local.
  --database NAME     D1 database binding/name. Default: d1media.
  --execute           Execute with Wrangler. Without this, only prints SQL.
  -h, --help          Show this help.

The script reads AUTH_SALT and the new password from hidden prompts unless
AUTH_SALT is already set in the environment.
EOF
}

hash_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r | awk '{print $1}'
    return
  fi
  echo "Missing sha256sum, shasum, or openssl" >&2
  return 1
}

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --username)
      username="${2:-}"
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

if [ -z "$username" ]; then
  read -rp "Username: " username
fi
if [ -z "$username" ]; then
  echo "Username is required" >&2
  exit 1
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

read -rsp "New password: " password
echo
read -rsp "Repeat new password: " password_again
echo
if [ "$password" != "$password_again" ]; then
  echo "Passwords do not match" >&2
  exit 1
fi
if [ -z "$password" ]; then
  echo "Password cannot be empty" >&2
  exit 1
fi

password_hash=$(printf '%s:%s' "$salt" "$password" | hash_sha256)
username_sql=$(sql_escape "$username")
unset salt password password_again

sql=$(cat <<EOF
UPDATE users
SET password_hash = '$password_hash'
WHERE username = '$username_sql';
SELECT changes() AS changed;
EOF
)

if [ "$execute" -ne 1 ]; then
  printf "\n-- D1 SQL\n%s\n" "$sql"
  exit 0
fi

if [ "$target_env" != "local" ]; then
  echo "About to update remote D1 database '$database' in env '$target_env' for user '$username'."
  read -rp "Type '$target_env/$username' to continue: " confirm
  if [ "$confirm" != "$target_env/$username" ]; then
    echo "Cancelled" >&2
    exit 1
  fi
fi

tmp_sql=$(mktemp "${TMPDIR:-/tmp}/lafuse-reset-password.XXXXXX.sql")
trap 'rm -f "$tmp_sql"' EXIT
chmod 600 "$tmp_sql"
printf "%s\n" "$sql" > "$tmp_sql"

if [ "$target_env" = "local" ]; then
  npx wrangler d1 execute "$database" --local --file "$tmp_sql"
else
  npx wrangler d1 execute "$database" --env "$target_env" --remote --file "$tmp_sql"
fi
