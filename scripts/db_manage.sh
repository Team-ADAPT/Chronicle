#!/usr/bin/env bash
# Chronicle Database Management Helper
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${DIR}"

export PYTHONPATH="${DIR}/src:${DIR}:${PYTHONPATH}"

if [ $# -eq 0 ]; then
    echo "Usage: ./scripts/db_manage.sh [migrate|status|retention|profile|ingest] [options]"
    exec python3 -m chronicle.db --help
fi

exec python3 -m chronicle.db "$@"
