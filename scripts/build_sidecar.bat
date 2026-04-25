@echo off
:: ============================================
:: build_sidecar.bat
:: Compiles the Python API server into a standalone
:: binary using PyInstaller, then copies it to the
:: Tauri sidecar directory (Windows).
:: ============================================

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
set APP_DIR=%PROJECT_ROOT%\app
set SIDECAR_DIR=%PROJECT_ROOT%\dashboard\src-tauri\sidecars

echo.
echo  Building USB Defender API sidecar (Windows)...
echo    App dir:     %APP_DIR%
echo    Sidecar dir: %SIDECAR_DIR%
echo.

:: Ensure sidecar directory exists
if not exist "%SIDECAR_DIR%" mkdir "%SIDECAR_DIR%"

:: Build the binary
"%PROJECT_ROOT%\.venv\Scripts\pyinstaller" ^
    --onefile ^
    --name "usb-defender-api" ^
    --distpath "%SIDECAR_DIR%" ^
    --workpath "%TEMP%\pyinstaller-work" ^
    --specpath "%TEMP%\pyinstaller-spec" ^
    --clean ^
    --noconfirm ^
    --add-data "%APP_DIR%\signatures.json;." ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.loops ^
    --hidden-import uvicorn.loops.auto ^
    --hidden-import uvicorn.protocols ^
    --hidden-import uvicorn.protocols.http ^
    --hidden-import uvicorn.protocols.http.auto ^
    --hidden-import uvicorn.protocols.websockets ^
    --hidden-import uvicorn.protocols.websockets.auto ^
    --hidden-import uvicorn.lifespan ^
    --hidden-import uvicorn.lifespan.on ^
    "%APP_DIR%\api.py"

:: Rename with target triple (Tauri requirement)
if exist "%SIDECAR_DIR%\usb-defender-api.exe" (
    copy "%SIDECAR_DIR%\usb-defender-api.exe" "%SIDECAR_DIR%\usb-defender-api-x86_64-pc-windows-msvc.exe"
    echo.
    echo  Sidecar built successfully!
    echo    Binary: %SIDECAR_DIR%\usb-defender-api-x86_64-pc-windows-msvc.exe
) else (
    echo  Build failed -- binary not found
    exit /b 1
)
