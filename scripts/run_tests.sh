#!/usr/bin/env bash
# Chronicle Test Runner
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${DIR}"

echo "=================================================="
echo " Running Chronicle Test Suites"
echo "=================================================="

export PYTHONPATH="${DIR}/src:${DIR}:${PYTHONPATH}"

if [ -x "${DIR}/.venv/bin/pytest" ]; then
    "${DIR}/.venv/bin/pytest" tests/ ML/tests/ -v "$@"
elif command -v pytest >/dev/null 2>&1; then
    pytest tests/ ML/tests/ -v "$@"
elif [ -x "${DIR}/.venv/bin/python" ]; then
    "${DIR}/.venv/bin/python" -m unittest discover tests -v "$@"
else
    python3 -m unittest discover tests -v "$@"
fi

echo "=================================================="
echo " All tests executed successfully!"
echo "=================================================="
