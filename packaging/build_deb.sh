#!/usr/bin/env bash
# ==============================================================================
# Chronicle v1.0.0 — Multi-Architecture Debian (.deb) Package Builder
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
    echo "=================================================="

    # 1. Clean previous build artifacts
    rm -rf "${PKG_DIR}" "${OUTPUT_DEB}"

    # 2. Create package directory layout
    mkdir -p "${PKG_DIR}/DEBIAN"
    mkdir -p "${PKG_DIR}/opt/chronicle/ui"
    mkdir -p "${PKG_DIR}/opt/chronicle/src/chronicle"
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

    # 4. Copy application files into /opt/chronicle
    cp app.py "${PKG_DIR}/opt/chronicle/"
    cp requirements.txt "${PKG_DIR}/opt/chronicle/"
    cp -r ui/* "${PKG_DIR}/opt/chronicle/ui/"
    cp -r src/* "${PKG_DIR}/opt/chronicle/src/"
    cp database/schema.sql "${PKG_DIR}/opt/chronicle/database/"

    if [ -d "ML/models" ]; then
        cp -r ML/models/* "${PKG_DIR}/opt/chronicle/ML/models/"
    fi

    # Clean up pycache and temporary files
    find "${PKG_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "${PKG_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true
    find "${PKG_DIR}" -type f -name ".DS_Store" -delete 2>/dev/null || true

    # Optional PyInstaller standalone compilation (Linux)
    if [[ "$*" == *"--compile"* ]] || [[ "$2" == "--compile" ]]; then
        if command -v pyinstaller >/dev/null 2>&1; then
            echo "--> Compiling standalone native ELF binary via PyInstaller..."
            pyinstaller --onefile \
                --name chronicle-bin \
                --paths src \
                --add-data "ui:ui" \
                --add-data "ML/models:ML/models" \
                --distpath "${PKG_DIR}/opt/chronicle" \
                --workpath /tmp/chronicle_build \
                --specpath /tmp/chronicle_build \
                app.py
            rm -rf /tmp/chronicle_build
        else
            echo "Warning: 'pyinstaller' not found; continuing with portable script runtime."
        fi
    fi

    # 5. Create the Master Launcher Script
    cat << 'EOF' > "${PKG_DIR}/opt/chronicle/chronicle"
#!/usr/bin/env bash
# ==============================================================================
# Chronicle v1.0.0 — Production Application Launcher
# ==============================================================================
set -e

# Resolve target installation directory even when invoked via symlink
CHRONICLE_HOME="/opt/chronicle"
if [ ! -d "${CHRONICLE_HOME}" ] || [ ! -f "${CHRONICLE_HOME}/app.py" ]; then
    TARGET_SOURCE="${BASH_SOURCE[0]}"
    while [ -h "${TARGET_SOURCE}" ]; do
        TARGET_DIR="$(cd -P "$(dirname "${TARGET_SOURCE}")" >/dev/null 2>&1 && pwd)"
        TARGET_SOURCE="$(readlink "${TARGET_SOURCE}")"
        [[ ${TARGET_SOURCE} != /* ]] && TARGET_SOURCE="${TARGET_DIR}/${TARGET_SOURCE}"
    done
    CHRONICLE_HOME="$(cd -P "$(dirname "${TARGET_SOURCE}")" >/dev/null 2>&1 && pwd)"
fi

DIR="${CHRONICLE_HOME}"
cd "${DIR}"
export PYTHONPATH="${DIR}/src:${DIR}:${PYTHONPATH}"

# 1. Prefer compiled native binary if present
if [ -x "${DIR}/chronicle-bin" ]; then
    exec "${DIR}/chronicle-bin" "$@"
fi

# 2. Check for isolated virtualenv inside /opt/chronicle/.venv
if [ -x "${DIR}/.venv/bin/python3" ]; then
    exec "${DIR}/.venv/bin/python3" "${DIR}/app.py" "$@"
fi

# 3. Fallback to host system python3
if command -v python3 >/dev/null 2>&1; then
    exec python3 "${DIR}/app.py" "$@"
else
    echo "Error: Python 3 is required to run Chronicle." >&2
    exit 1
fi
EOF
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
    echo " • Universal (all architectures): chronicle_1.0.0-1_all.deb"
    echo " • ARM64 (Apple Silicon / Graviton): chronicle_1.0.0-1_arm64.deb"
    echo " • AMD64 (Intel / x86_64 Linux):    chronicle_1.0.0-1_amd64.deb"
    echo "=================================================="
else
    build_package_for_arch "${TARGET_ARCH}"
fi
