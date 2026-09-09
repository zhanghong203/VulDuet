#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BOOTSTRAP="${PYTHON_BOOTSTRAP:-python3}"
"$PYTHON_BOOTSTRAP" -m venv .venv

.venv/bin/python -m pip install --upgrade pip wheel setuptools

if [[ "${INSTALL_TORCH:-1}" == "1" ]]; then
  # Override TORCH_INDEX_URL for a server with a different CUDA version.
  TORCH_INDEX_URL="${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cu121}"
  .venv/bin/python -m pip install torch --index-url "$TORCH_INDEX_URL"
fi

.venv/bin/python -m pip install -r server_v4/requirements-server.txt

if [[ ! -f src/config/config.local.yml ]]; then
  cp src/config/config.local.example.yml src/config/config.local.yml
  echo "Created src/config/config.local.yml. Insert the API key before running."
fi

chmod +x server_v4/run_primevul_v4.sh server_v4/run_sven_v4.sh
echo "Setup complete. Next: .venv/bin/python server_v4/check_server.py"
