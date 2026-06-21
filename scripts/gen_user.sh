#!/bin/bash
set -euo pipefail

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

salt="${AUTH_SALT:-}"
if [ -z "$salt" ]; then
  read -rsp "AUTH_SALT: " salt
  echo
fi
read -rp "Username: " username
read -rsp "Password: " passwd; echo
password_hash=$(printf '%s:%s' "$salt" "$passwd" | hash_sha256)
username_sql=$(sql_escape "$username")
unset salt passwd
printf "\n\n-- the D1 query\n"
echo "INSERT INTO users (username, password_hash, role) "
echo "  VALUES ('$username_sql', '$password_hash', 'admin');"
