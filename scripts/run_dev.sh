#!/usr/bin/env bash
# Chronicle Development Launcher
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${DIR}"

echo "=================================================="
echo " Starting Chronicle (Development Mode)"
echo "=================================================="

# Export PYTHONPATH to ensure both src and root packages resolve
export PYTHONPATH="${DIR}/src:${DIR}:${PYTHONPATH}"

# Determine Python executable
PYTHON_BIN="python3"
if [ -x "${DIR}/.venv/bin/python" ]; then
    PYTHON_BIN="${DIR}/.venv/bin/python"
fi

# Run app.py
exec "${PYTHON_BIN}" app.py "$@"
