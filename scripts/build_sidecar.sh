#!/bin/bash
# ============================================
# build_sidecar.sh
# Compiles BOTH binaries Tauri needs into the sidecar directory:
#   1. usb-defender-api      — the FastAPI backend
#   2. usb-defender-portable — the standalone scanner deployed by "Arm USB"
#
# Both are declared in tauri.conf.json externalBin, so `tauri build` and
# `tauri dev` fail unless both exist with the host target triple appended.
# ============================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$PROJECT_ROOT/app"
PORTABLE_DIR="$PROJECT_ROOT/portable"
SIDECAR_DIR="$PROJECT_ROOT/dashboard/src-tauri/sidecars"

# Prefer the project venv, fall back to whatever python is on PATH.
if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python"
else
    PYTHON="$(command -v python3 || command -v python)"
fi

echo "🔨 Building USB Defender sidecars"
echo "   Python:      $PYTHON"
echo "   Sidecar dir: $SIDECAR_DIR"

# Determine the host target triple — Tauri requires this suffix.
ARCH="$(uname -m)"
OS="$(uname -s)"
case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64) TRIPLE="aarch64-apple-darwin" ;;
            *)     TRIPLE="x86_64-apple-darwin" ;;
        esac
        ;;
    *)
        case "$ARCH" in
            x86_64)  TRIPLE="x86_64-unknown-linux-gnu" ;;
            aarch64) TRIPLE="aarch64-unknown-linux-gnu" ;;
            *)       TRIPLE="$ARCH-unknown-linux-gnu" ;;
        esac
        ;;
esac
echo "   Target:      $TRIPLE"
echo ""

# Ensure build tooling and runtime deps are present.
if ! "$PYTHON" -c "import PyInstaller" 2>/dev/null; then
    echo "📦 Installing PyInstaller..."
    "$PYTHON" -m pip install pyinstaller -q
fi
if ! "$PYTHON" -c "import websockets" 2>/dev/null; then
    echo "📦 Installing project requirements (websockets missing)..."
    "$PYTHON" -m pip install -r "$PROJECT_ROOT/requirements.txt" -q
fi

mkdir -p "$SIDECAR_DIR"

# ── 1. The API sidecar ───────────────────────────────────────────────
echo "▶ Building usb-defender-api..."
"$PYTHON" -m PyInstaller \
    --onefile \
    --name "usb-defender-api" \
    --distpath "$SIDECAR_DIR" \
    --workpath "/tmp/pyinstaller-work" \
    --specpath "/tmp/pyinstaller-spec" \
    --clean \
    --noconfirm \
    --log-level WARN \
    --add-data "$APP_DIR/signatures.json:." \
    --add-data "$PORTABLE_DIR/scan.sh:." \
    --add-data "$PORTABLE_DIR/scan.bat:." \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.loops \
    --hidden-import uvicorn.loops.auto \
    --hidden-import uvicorn.protocols \
    --hidden-import uvicorn.protocols.http \
    --hidden-import uvicorn.protocols.http.auto \
    --hidden-import uvicorn.protocols.websockets \
    --hidden-import uvicorn.protocols.websockets.auto \
    --hidden-import uvicorn.protocols.websockets.websockets_impl \
    --hidden-import uvicorn.lifespan \
    --hidden-import uvicorn.lifespan.on \
    --collect-submodules websockets \
    "$APP_DIR/api.py"

# ── 2. The portable scanner ──────────────────────────────────────────
echo "▶ Building usb-defender-portable..."
"$PYTHON" -m PyInstaller \
    --onefile \
    --name "usb-defender-portable" \
    --distpath "$SIDECAR_DIR" \
    --workpath "/tmp/pyinstaller-work" \
    --specpath "/tmp/pyinstaller-spec" \
    --clean \
    --noconfirm \
    --log-level WARN \
    "$PORTABLE_DIR/usb_defender_portable.py"

# ── 3. Append the target triple ──────────────────────────────────────
for base in usb-defender-api usb-defender-portable; do
    if [ ! -f "$SIDECAR_DIR/$base" ]; then
        echo "❌ Build failed — $SIDECAR_DIR/$base not found"
        exit 1
    fi
    cp "$SIDECAR_DIR/$base" "$SIDECAR_DIR/$base-$TRIPLE"
    chmod +x "$SIDECAR_DIR/$base-$TRIPLE"
done

# ── 4. Verify the API sidecar actually works ─────────────────────────
echo ""
echo "▶ Verifying the API sidecar (health, WebSockets, persistent state)..."
"$PYTHON" "$SCRIPT_DIR/verify_sidecar.py" "$SIDECAR_DIR/usb-defender-api"

echo ""
echo "✅ Sidecars built successfully:"
ls -lh "$SIDECAR_DIR"/*-"$TRIPLE"
