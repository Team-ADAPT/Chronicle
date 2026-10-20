#!/usr/bin/env bash
# Chronicle Database Management Helper
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${DIR}"

export PYTHONPATH="${DIR}/src:${DIR}:${PYTHONPATH}"

PYTHON_BIN="python3"
if [ -x "${DIR}/.venv/bin/python" ]; then
    PYTHON_BIN="${DIR}/.venv/bin/python"
fi

if [ $# -eq 0 ]; then
    echo "Usage: ./scripts/db_manage.sh [migrate|status|retention|profile|ingest] [options]"
    exec "${PYTHON_BIN}" -m chronicle.db --help
fi

exec "${PYTHON_BIN}" -m chronicle.db "$@"
