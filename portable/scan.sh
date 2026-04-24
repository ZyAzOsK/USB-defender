#!/bin/bash
# USB Defender Portable Scanner — Linux/macOS Launcher
# Make executable: chmod +x scan.sh
# Then double-click or run: ./scan.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  =========================================="
echo "    USB Defender - Portable Scanner"
echo "  =========================================="
echo ""

# Try the compiled binary first
if [ -f "$SCRIPT_DIR/usb-defender-linux" ]; then
    echo "  [*] Running compiled scanner..."
    "$SCRIPT_DIR/usb-defender-linux"
    exit $?
fi

if [ -f "$SCRIPT_DIR/usb-defender-macos" ]; then
    echo "  [*] Running compiled scanner..."
    "$SCRIPT_DIR/usb-defender-macos"
    exit $?
fi

# Fall back to Python
if command -v python3 &> /dev/null; then
    echo "  [*] Running with Python3..."
    python3 "$SCRIPT_DIR/usb_defender_portable.py"
    exit $?
elif command -v python &> /dev/null; then
    echo "  [*] Running with Python..."
    python "$SCRIPT_DIR/usb_defender_portable.py"
    exit $?
fi

echo "  [!] ERROR: Python is not installed on this system."
echo "  [!] Please install Python 3.8+ or use the pre-compiled binary."
exit 1
