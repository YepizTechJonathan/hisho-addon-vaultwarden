#!/usr/bin/env bash
# Remove (Install in Hisho's undo): stop Vaultwarden and take its tailnet address off. Its data stays in ~/vaultwarden.
set -euo pipefail
HISHO_REPO="${HISHO_REPO:-$HOME/code/hisho}"
exec bash "$HISHO_REPO/deploy/vaultwarden/install.sh" --remove
