#!/usr/bin/env bash
# ==============================================================================
# Chronicle v1.0.0 — Multi-Architecture Debian (.deb) Package Builder
# Produces protected, compiled black-box application packages (no raw source code).
# ==============================================================================
set -e

VERSION="1.0.0-1"
TARGET_ARCH="${1:-all_targets}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

build_package_for_arch() {
    local ARCH="$1"
    local PKG_DIR="chronicle_${VERSION}_${ARCH}"
    local OUTPUT_DEB="${PKG_DIR}.deb"

    echo "=================================================="
    echo " Building Chronicle Debian Package: ${OUTPUT_DEB}"
    echo " Architecture: ${ARCH}"
    echo " Mode: Black-Box Compiled Binary Delivery"
    echo "=================================================="

    # 1. Clean previous build artifacts
    rm -rf "${PKG_DIR}" "${OUTPUT_DEB}"

    # 2. Create package directory layout
    mkdir -p "${PKG_DIR}/DEBIAN"
    mkdir -p "${PKG_DIR}/opt/chronicle/ui"
    mkdir -p "${PKG_DIR}/opt/chronicle/database"
    mkdir -p "${PKG_DIR}/opt/chronicle/ML/models"
    mkdir -p "${PKG_DIR}/opt/chronicle/data"
    mkdir -p "${PKG_DIR}/usr/share/applications"
    mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps"
    mkdir -p "${PKG_DIR}/usr/local/bin"
    mkdir -p "${PKG_DIR}/lib/systemd/system"

    # 3. Create architecture-specific Debian control file
    sed "s/^Architecture:.*/Architecture: ${ARCH}/" packaging/DEBIAN/control > "${PKG_DIR}/DEBIAN/control"

    if [ -f "packaging/DEBIAN/postinst" ]; then
        cp packaging/DEBIAN/postinst "${PKG_DIR}/DEBIAN/"
        chmod 755 "${PKG_DIR}/DEBIAN/postinst"
    fi
    if [ -f "packaging/DEBIAN/prerm" ]; then
        cp packaging/DEBIAN/prerm "${PKG_DIR}/DEBIAN/"
        chmod 755 "${PKG_DIR}/DEBIAN/prerm"
    fi
    if [ -f "packaging/DEBIAN/postrm" ]; then
        cp packaging/DEBIAN/postrm "${PKG_DIR}/DEBIAN/"
        chmod 755 "${PKG_DIR}/DEBIAN/postrm"
    fi

    # 4. Copy assets, models, and schema
    cp -r ui/* "${PKG_DIR}/opt/chronicle/ui/"
    cp database/schema.sql "${PKG_DIR}/opt/chronicle/database/"
    if [ -d "ML/models" ]; then
        cp -r ML/models/* "${PKG_DIR}/opt/chronicle/ML/models/"
    fi

    # 5. Compiled Application Build (Black-Box Protection)
    if command -v pyinstaller >/dev/null 2>&1; then
        echo "--> [PyInstaller] Compiling standalone native binary executable..."
        pyinstaller --onefile \
            --name chronicle-bin \
            --paths src \
            --add-data "ui:ui" \
            --add-data "ML/models:ML/models" \
            --add-data "database/schema.sql:database" \
            --hidden-import "chronicle" \
            --hidden-import "chronicle.pipeline" \
            --hidden-import "chronicle.collector" \
            --hidden-import "chronicle.ml_detector" \
            --hidden-import "chronicle.risk_engine" \
            --hidden-import "chronicle.storage" \
            --hidden-import "chronicle.tray" \
            --hidden-import "chronicle.service_api" \
            --hidden-import "chronicle.api" \
            --hidden-import "chronicle.config" \
            --distpath "${PKG_DIR}/opt/chronicle" \
            --workpath /tmp/chronicle_build \
            --specpath /tmp/chronicle_build \
            app.py
        rm -rf /tmp/chronicle_build
        chmod 755 "${PKG_DIR}/opt/chronicle/chronicle-bin"

        # Production Launcher runs the compiled native binary directly
        cat << 'EOF' > "${PKG_DIR}/opt/chronicle/chronicle"
#!/usr/bin/env bash
set -e
DIR="/opt/chronicle"
if [ ! -f "${DIR}/chronicle-bin" ]; then
    DIR="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
fi
cd "${DIR}"
exec "${DIR}/chronicle-bin" "$@"
EOF
    else
        echo "--> [Bytecode Compilation] Compiling into bytecode (.pyc) and stripping all raw .py source files..."
        mkdir -p "${PKG_DIR}/opt/chronicle/src"
        cp app.py "${PKG_DIR}/opt/chronicle/"
        cp -r src/* "${PKG_DIR}/opt/chronicle/src/"

        # Compile all to bytecode (.pyc) in place
        python3 -m compileall -b "${PKG_DIR}/opt/chronicle" >/dev/null 2>&1

        # Strip all raw Python source files completely
        find "${PKG_DIR}/opt/chronicle" -type f -name "*.py" -delete
        find "${PKG_DIR}/opt/chronicle" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

        cat << 'EOF' > "${PKG_DIR}/opt/chronicle/chronicle"
#!/usr/bin/env bash
set -e
DIR="/opt/chronicle"
if [ ! -f "${DIR}/app.pyc" ]; then
    DIR="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
fi
cd "${DIR}"
export PYTHONPATH="${DIR}/src:${DIR}:${PYTHONPATH}"
if command -v python3 >/dev/null 2>&1; then
    exec python3 "${DIR}/app.pyc" "$@"
else
    echo "Error: Python 3 runtime is required." >&2
    exit 1
fi
EOF
    fi

    # Final security scrub: ensure zero raw source code files exist in package
    find "${PKG_DIR}/opt/chronicle" -type f -name "*.py" -delete
    find "${PKG_DIR}" -type f -name ".DS_Store" -delete 2>/dev/null || true
    chmod 755 "${PKG_DIR}/opt/chronicle/chronicle"

    # Symlink to /usr/local/bin/chronicle
    ln -sf /opt/chronicle/chronicle "${PKG_DIR}/usr/local/bin/chronicle"

    # 6. Install systemd service unit
    if [ -f "packaging/chronicle.service" ]; then
        cp packaging/chronicle.service "${PKG_DIR}/lib/systemd/system/chronicle.service"
        chmod 644 "${PKG_DIR}/lib/systemd/system/chronicle.service"
    fi

    # 7. Install Desktop Entry and Application Icon
    cp packaging/chronicle.desktop "${PKG_DIR}/usr/share/applications/"
    cp packaging/chronicle.png "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps/chronicle.png"

    # 8. Package Generation
    echo "--> Packaging ${OUTPUT_DEB}..."
    if command -v dpkg-deb >/dev/null 2>&1; then
        dpkg-deb --build --root-owner-group "${PKG_DIR}"
    else
        python3 packaging/make_deb.py "${PKG_DIR}" "${OUTPUT_DEB}"
    fi

    local PY_FILES_COUNT
    PY_FILES_COUNT=$(find "${PKG_DIR}/opt/chronicle" -name "*.py" 2>/dev/null | wc -l || echo 0)
    echo " Internal Source Security Check: ${PY_FILES_COUNT} .py source files exposed (0 expected)."
    echo " Successfully generated: ${OUTPUT_DEB} ($(ls -lh "${OUTPUT_DEB}" | awk '{print $5}'))"
    rm -rf "${PKG_DIR}"
}

if [ "${TARGET_ARCH}" = "all_targets" ]; then
    echo "Building all target packages: all, arm64, amd64"
    build_package_for_arch "all"
    build_package_for_arch "arm64"
    build_package_for_arch "amd64"
    echo ""
    echo "=================================================="
    echo " All Debian Packages Built Successfully!"
    echo " • Universal: chronicle_1.0.0-1_all.deb"
    echo " • ARM64:     chronicle_1.0.0-1_arm64.deb"
    echo " • AMD64:     chronicle_1.0.0-1_amd64.deb"
    echo " Internal source code completely protected."
    echo "=================================================="
else
    build_package_for_arch "${TARGET_ARCH}"
fi
