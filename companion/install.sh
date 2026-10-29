#!/usr/bin/env bash
# Install in Hisho (src/hisho/companion.py runs this on the Core machine): Vaultwarden in Docker, on the tailnet at
# https://<core>:5443, data in ~/vaultwarden. Hisho's own install does the work (pinned image, admin token hashed,
# the token itself handed to Hisho as a secret). Afterwards the add-on makes Hisho's account by itself.
set -euo pipefail
HISHO_REPO="${HISHO_REPO:-$HOME/code/hisho}"
exec bash "$HISHO_REPO/deploy/vaultwarden/install.sh"
