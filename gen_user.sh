#!/bin/bash
set -u
salt=6db26ef6
read -rp "Username: " username
read -rsp "Password: " passwd; echo
password_hash=$(echo -n "$salt:$passwd" | sha256sum | cut -d' ' -f1)
printf "\n\n-- the D1 query\n"
echo "INSERT INTO users (username, password_hash, role) "
echo "  VALUES ('$username', '$password_hash', 'admin');"