#!/usr/bin/env bash
# Chronicle Debian .deb Package Builder
set -e

VERSION="0.2.0-1"
ARCH="amd64"
PKG_DIR="chronicle_${VERSION}_${ARCH}"

echo "=================================================="
echo " Building Chronicle Debian Package: ${PKG_DIR}.deb"
echo "=================================================="

# 1. Clean previous build artifacts
rm -rf "${PKG_DIR}" "${PKG_DIR}.deb"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/chronicle/ui"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${PKG_DIR}/usr/local/bin"

# 2. Copy control file
cp packaging/DEBIAN/control "${PKG_DIR}/DEBIAN/"

# 3. Copy application files into /opt/chronicle
cp app.py "${PKG_DIR}/opt/chronicle/"
cp -r ui/* "${PKG_DIR}/opt/chronicle/ui/"

# If pyinstaller binary exists, include compiled binary; otherwise create launcher script
cat << 'EOF' > "${PKG_DIR}/opt/chronicle/chronicle"
#!/usr/bin/env bash
# Chronicle App Launcher
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
    exec python3 "${DIR}/app.py" "$@"
else
    echo "Error: python3 is required to run Chronicle." >&2
    exit 1
fi
EOF
chmod +x "${PKG_DIR}/opt/chronicle/chronicle"

# Symlink to /usr/local/bin/chronicle
ln -sf /opt/chronicle/chronicle "${PKG_DIR}/usr/local/bin/chronicle"

# 4. Copy Desktop Entry and App Icon
cp packaging/chronicle.desktop "${PKG_DIR}/usr/share/applications/"
cp packaging/chronicle.png "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps/chronicle.png"

# 5. Build Debian package using dpkg-deb
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "${PKG_DIR}"
    echo "=================================================="
    echo " Successfully generated: ${PKG_DIR}.deb"
    echo " To install on Ubuntu/Debian:"
    echo "   sudo dpkg -i ${PKG_DIR}.deb"
    echo "=================================================="
else
    echo "Warning: 'dpkg-deb' not found in PATH (typical on non-Debian/macOS systems)."
    echo "Package tree created at: ./${PKG_DIR}"
    echo "Run this script on a Linux Debian/Ubuntu machine to build the final .deb binary."
fi
