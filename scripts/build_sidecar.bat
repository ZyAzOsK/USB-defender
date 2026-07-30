@echo off
setlocal enabledelayedexpansion
:: ============================================
:: build_sidecar.bat
:: Compiles BOTH binaries Tauri needs into the sidecar directory (Windows):
::   1. usb-defender-api      - the FastAPI backend
::   2. usb-defender-portable - the scanner deployed by "Arm USB"
::
:: Both are declared in tauri.conf.json externalBin, so `tauri build` and
:: `tauri dev` fail unless both exist with the target triple appended.
:: ============================================

set SCRIPT_DIR=%~dp0
for %%I in ("%SCRIPT_DIR%..") do set PROJECT_ROOT=%%~fI
set APP_DIR=%PROJECT_ROOT%\app
set PORTABLE_DIR=%PROJECT_ROOT%\portable
set SIDECAR_DIR=%PROJECT_ROOT%\dashboard\src-tauri\sidecars
set TRIPLE=x86_64-pc-windows-msvc

:: Prefer the project venv, else fall back to PATH.
set PYTHON=%PROJECT_ROOT%\.venv\Scripts\python.exe
if not exist "%PYTHON%" set PYTHON=python

echo.
echo  Building USB Defender sidecars (Windows)
echo    Python:      %PYTHON%
echo    Sidecar dir: %SIDECAR_DIR%
echo    Target:      %TRIPLE%
echo.

if not exist "%SIDECAR_DIR%" mkdir "%SIDECAR_DIR%"

:: Ensure build tooling and runtime deps are present.
"%PYTHON%" -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo  Installing PyInstaller...
    "%PYTHON%" -m pip install pyinstaller -q
)
"%PYTHON%" -c "import websockets" 2>nul
if errorlevel 1 (
    echo  Installing project requirements ^(websockets missing^)...
    "%PYTHON%" -m pip install -r "%PROJECT_ROOT%\requirements.txt" -q
)

:: --- 1. The API sidecar -------------------------------------------------
:: NOTE: --add-data uses ';' as the separator on Windows, not ':'.
echo  Building usb-defender-api...
"%PYTHON%" -m PyInstaller ^
    --onefile ^
    --name "usb-defender-api" ^
    --distpath "%SIDECAR_DIR%" ^
    --workpath "%TEMP%\pyinstaller-work" ^
    --specpath "%TEMP%\pyinstaller-spec" ^
    --clean ^
    --noconfirm ^
    --log-level WARN ^
    --add-data "%APP_DIR%\signatures.json;." ^
    --add-data "%PORTABLE_DIR%\scan.sh;." ^
    --add-data "%PORTABLE_DIR%\scan.bat;." ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.loops ^
    --hidden-import uvicorn.loops.auto ^
    --hidden-import uvicorn.protocols ^
    --hidden-import uvicorn.protocols.http ^
    --hidden-import uvicorn.protocols.http.auto ^
    --hidden-import uvicorn.protocols.websockets ^
    --hidden-import uvicorn.protocols.websockets.auto ^
    --hidden-import uvicorn.protocols.websockets.websockets_impl ^
    --hidden-import uvicorn.lifespan ^
    --hidden-import uvicorn.lifespan.on ^
    --collect-submodules websockets ^
    "%APP_DIR%\api.py"
if errorlevel 1 goto :failed

:: --- 2. The portable scanner --------------------------------------------
echo  Building usb-defender-portable...
"%PYTHON%" -m PyInstaller ^
    --onefile ^
    --name "usb-defender-portable" ^
    --distpath "%SIDECAR_DIR%" ^
    --workpath "%TEMP%\pyinstaller-work" ^
    --specpath "%TEMP%\pyinstaller-spec" ^
    --clean ^
    --noconfirm ^
    --log-level WARN ^
    "%PORTABLE_DIR%\usb_defender_portable.py"
if errorlevel 1 goto :failed

:: --- 3. Append the target triple ---------------------------------------
for %%B in (usb-defender-api usb-defender-portable) do (
    if not exist "%SIDECAR_DIR%\%%B.exe" (
        echo  Build failed -- %%B.exe not found
        goto :failed
    )
    copy /Y "%SIDECAR_DIR%\%%B.exe" "%SIDECAR_DIR%\%%B-%TRIPLE%.exe" >nul
    echo    prepared %%B-%TRIPLE%.exe
)

:: --- 4. Verify the API sidecar actually works ---------------------------
echo.
echo  Verifying the API sidecar (health, WebSockets, persistent state)...
"%PYTHON%" "%SCRIPT_DIR%verify_sidecar.py" "%SIDECAR_DIR%\usb-defender-api.exe"
if errorlevel 1 goto :failed

echo.
echo  Sidecars built successfully.
dir /b "%SIDECAR_DIR%"
exit /b 0

:failed
echo.
echo  BUILD FAILED
exit /b 1
