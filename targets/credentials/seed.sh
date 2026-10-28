#!/usr/bin/env bash
# Seed the fake credential store (C4): the credential_access target.
#
# Creates the secret files the baseline trace reads (file:///run/secrets/token,
# file:///run/secrets/db_password). Runs in the harness container entrypoint
# (M4/M5) so reads are kernel-observable from harness-context processes.
# Fixed contents for determinism across runs.
#
# Override the destination with SECRETS_DIR (default /run/secrets).
set -euo pipefail

SECRETS_DIR="${SECRETS_DIR:-/run/secrets}"

mkdir -p "$SECRETS_DIR"
# Fixed placeholder values; the testbed assumes no real adversary (main.tex).
printf 'baseline-token-0f3a\n'  > "$SECRETS_DIR/token"
printf 'baseline-db-password-9c2e\n' > "$SECRETS_DIR/db_password"
chmod 0400 "$SECRETS_DIR/token" "$SECRETS_DIR/db_password"

echo "credentials: seeded $(ls "$SECRETS_DIR" | tr '\n' ' ')in $SECRETS_DIR"