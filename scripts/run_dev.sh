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

# Run app.py
exec python3 app.py "$@"
