#!/usr/bin/env bash
# Launch the steer-control control panel.
# Run this in a terminal (it stays running and prints the URL).
set -e
cd "$(dirname "$0")/.."
source .venv/bin/activate
export USE_TF=0
export PATH="$HOME/.local/bin:$PATH"   # so the server can find the `claude` CLI for S
exec python webapp/server.py
