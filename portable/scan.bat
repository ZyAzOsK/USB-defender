@echo off
:: USB Defender Portable Scanner — Windows Launcher
:: Double-click this file to scan the USB drive.
:: Requires Python 3.8+ OR the compiled .exe binary.

title USB Defender - Portable Scanner
color 0B

echo.
echo  ==========================================
echo    USB Defender - Portable Scanner
echo  ==========================================
echo.

:: Try the compiled binary first
if exist "%~dp0usb-defender.exe" (
    echo  [*] Running compiled scanner...
    "%~dp0usb-defender.exe"
    goto :done
)

if exist "%~dp0USBDefender.exe" (
    echo  [*] Running compiled scanner...
    "%~dp0USBDefender.exe"
    goto :done
)

:: Fall back to Python
where python >nul 2>&1
if %errorlevel% equ 0 (
    echo  [*] Running with Python...
    python "%~dp0usb_defender_portable.py"
    goto :done
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    echo  [*] Running with Python3...
    python3 "%~dp0usb_defender_portable.py"
    goto :done
)

echo  [!] ERROR: Python is not installed on this system.
echo  [!] Please install Python 3.8+ from https://python.org
echo  [!] Or use the pre-compiled .exe binary instead.

:done
echo.
echo  Press any key to close...
pause >nul
