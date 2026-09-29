#!/usr/bin/env bash
# Bases et rôles distincts (M0-T03, ADR 0003), une fois sur volume vide.
# Aucun mot de passe littéral ni en argument.
set -euo pipefail
for v in POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD; do
  [[ "${!v:-}" =~ ^[0-9a-f]{64}$ ]] || { echo "postgres-init : $v absent ou mal formé." >&2; exit 2; }
done
psql -v ON_ERROR_STOP=1 --no-psqlrc --username postgres --dbname postgres <<'SQL'
SET log_min_error_statement = panic;
SET log_statement = none;
\getenv temporal_pw TEMPORAL_DB_PASSWORD
\getenv rempart_pw REMPART_DB_PASSWORD
CREATE ROLE temporal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'temporal_pw';
CREATE ROLE rempart_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE rempart LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'rempart_pw';
CREATE DATABASE temporal OWNER temporal;
CREATE DATABASE temporal_visibility OWNER temporal;
CREATE DATABASE rempart OWNER rempart_owner;
REVOKE CONNECT, TEMPORARY ON DATABASE temporal, temporal_visibility, rempart, postgres, template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE rempart TO rempart;
SQL
