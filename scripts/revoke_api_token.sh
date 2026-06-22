#!/bin/bash
set -euo pipefail

token_id=""
database="d1media"
target_env="local"
execute=0

usage() {
  cat <<'EOF'
Usage:
  ./scripts/revoke_api_token.sh <token-id>
  ./scripts/revoke_api_token.sh --env production --execute <token-id>

Options:
  --env NAME         local or a Wrangler environment name. Default: local.
  --database NAME    D1 database binding/name. Default: d1media.
  --execute          Execute with Wrangler. Without this, only prints SQL.
  -h, --help         Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
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
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [ -n "$token_id" ]; then
        echo "Unexpected argument: $1" >&2
        usage >&2
        exit 1
      fi
      token_id="$1"
      shift
      ;;
  esac
done

if [ -z "$token_id" ]; then
  read -rp "Token id: " token_id
fi
if ! printf '%s' "$token_id" | grep -Eq '^[a-z0-9]{12}$'; then
  echo "Invalid token id" >&2
  exit 1
fi

sql=$(cat <<EOF
UPDATE api_tokens
SET revoked_at = $(date +%s)
WHERE id = '$token_id';
SELECT changes() AS changed;
EOF
)

printf "%s\n" "$sql"

if [ "$execute" -ne 1 ]; then
  exit 0
fi

if [ "$target_env" != "local" ]; then
  echo
  echo "About to revoke remote API token '$token_id' in D1 database '$database' env '$target_env'."
  read -rp "Type '$target_env/$token_id' to continue: " confirm
  if [ "$confirm" != "$target_env/$token_id" ]; then
    echo "Cancelled" >&2
    exit 1
  fi
fi

tmp_sql=$(mktemp "${TMPDIR:-/tmp}/lafuse-revoke-token.XXXXXX.sql")
trap 'rm -f "$tmp_sql"' EXIT
chmod 600 "$tmp_sql"
printf "%s\n" "$sql" > "$tmp_sql"

if [ "$target_env" = "local" ]; then
  npx wrangler d1 execute "$database" --local --file "$tmp_sql"
else
  npx wrangler d1 execute "$database" --env "$target_env" --remote --file "$tmp_sql"
fi
