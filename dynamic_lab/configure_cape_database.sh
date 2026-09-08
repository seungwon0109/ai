#!/usr/bin/env bash
set -euo pipefail

password_file=/root/.cape_db_password
if [[ ! -s "$password_file" ]]; then
    echo "CAPE database password file is missing." >&2
    exit 1
fi

read -r cape_db_password < "$password_file"

if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='cape'" | grep -q 1; then
    runuser -u postgres -- createuser --login cape
fi

printf '%s\n' "ALTER ROLE cape PASSWORD :'cape_password';" |
    runuser -u postgres -- psql \
        --set=ON_ERROR_STOP=1 \
        --set=cape_password="$cape_db_password"

if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='cape'" | grep -q 1; then
    runuser -u postgres -- createdb --owner=cape cape
fi

echo "CAPE PostgreSQL role and database are ready."
