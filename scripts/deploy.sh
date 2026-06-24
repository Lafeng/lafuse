#!/bin/bash
set -euo pipefail

target_env="production"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/deploy.sh
  ./scripts/deploy.sh --env production

Options:
  --env NAME   Wrangler environment. Default: production.
  -h, --help   Show this help.

APP_VERSION may be set explicitly. Otherwise this script uses:
  git describe --tags --always --dirty
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env)
      target_env="${2:-}"
      shift 2
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

if [ -z "$target_env" ]; then
  echo "Environment is required" >&2
  exit 1
fi

version="${APP_VERSION:-$(git describe --tags --always --dirty)}"
if [ -z "$version" ]; then
  echo "Unable to resolve APP_VERSION" >&2
  exit 1
fi

echo "Deploying Lafuse ${version} to ${target_env}"
npx wrangler deploy --env "$target_env" --keep-vars --var "APP_VERSION:$version" --message "Lafuse ${version}"
