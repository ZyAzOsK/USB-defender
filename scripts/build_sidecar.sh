#!/bin/bash
# ============================================
# build_sidecar.sh
# Compiles the Python API server into a standalone
# binary using PyInstaller, then copies it to the
# Tauri sidecar directory.
# ============================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$PROJECT_ROOT/app"
SIDECAR_DIR="$PROJECT_ROOT/dashboard/src-tauri/sidecars"

echo "🔨 Building USB Defender API sidecar..."
echo "   App dir:     $APP_DIR"
echo "   Sidecar dir: $SIDECAR_DIR"

# Ensure PyInstaller is installed
if ! "$PROJECT_ROOT/.venv/bin/python" -c "import PyInstaller" 2>/dev/null; then
    echo "📦 Installing PyInstaller..."
    "$PROJECT_ROOT/.venv/bin/pip" install pyinstaller -q
fi

# Build the binary
"$PROJECT_ROOT/.venv/bin/pyinstaller" \
    --onefile \
    --name "usb-defender-api" \
    --distpath "$SIDECAR_DIR" \
    --workpath "/tmp/pyinstaller-work" \
    --specpath "/tmp/pyinstaller-spec" \
    --clean \
    --noconfirm \
    --add-data "$APP_DIR/signatures.json:." \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.loops \
    --hidden-import uvicorn.loops.auto \
    --hidden-import uvicorn.protocols \
    --hidden-import uvicorn.protocols.http \
    --hidden-import uvicorn.protocols.http.auto \
    --hidden-import uvicorn.protocols.websockets \
    --hidden-import uvicorn.protocols.websockets.auto \
    --hidden-import uvicorn.lifespan \
    --hidden-import uvicorn.lifespan.on \
    "$APP_DIR/api.py"

# Tauri expects sidecar name with target-triple suffix on Linux
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TRIPLE="x86_64-unknown-linux-gnu" ;;
    aarch64) TRIPLE="aarch64-unknown-linux-gnu" ;;
    *)       TRIPLE="$ARCH-unknown-linux-gnu" ;;
esac

# Rename to include target triple (Tauri requirement)
if [ -f "$SIDECAR_DIR/usb-defender-api" ]; then
    cp "$SIDECAR_DIR/usb-defender-api" "$SIDECAR_DIR/usb-defender-api-$TRIPLE"
    echo ""
    echo "✅ Sidecar built successfully!"
    echo "   Binary: $SIDECAR_DIR/usb-defender-api-$TRIPLE"
    ls -lh "$SIDECAR_DIR/usb-defender-api-$TRIPLE"
else
    echo "❌ Build failed — binary not found"
    exit 1
fi
