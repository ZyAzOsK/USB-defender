"""
paths.py
--------
Single source of truth for *where things live* on disk.

This exists because the API server ships as a PyInstaller `--onefile`
sidecar. In a frozen build, ``Path(__file__).parent`` resolves inside the
``_MEIPASS`` extraction directory, which is deleted when the process exits.
Anything written there (database, logs, edited signatures) is silently lost
on every restart. So writable state goes to a per-user data directory and
read-only bundled assets are read from the extraction directory.

Also holds the cross-platform path helpers, because a bare Windows drive
spec like ``D:`` is *drive-relative*, not the drive root — ``os.walk("D:")``
walks the current directory on D: instead of ``D:\\``.
"""

import os
import re
import sys
import platform
from pathlib import Path

APP_NAME = "USB Defender"

# ==============================
# Writable per-user data directory
# ==============================
def _default_data_dir() -> Path:
    system = platform.system()

    if system == "Windows":
        base = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / APP_NAME
        return Path.home() / "AppData" / "Roaming" / APP_NAME

    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME

    # Linux / BSD — follow the XDG basedir spec
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / "usb-defender"
    return Path.home() / ".local" / "share" / "usb-defender"


def get_data_dir() -> Path:
    """
    Return the writable directory for database, logs and user-edited
    signatures. Honours ``USB_DEFENDER_DATA_DIR`` so tests and portable
    setups can redirect it. Created on demand.
    """
    override = os.environ.get("USB_DEFENDER_DATA_DIR")
    data_dir = Path(override).expanduser() if override else _default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def is_frozen() -> bool:
    """True when running from a PyInstaller bundle."""
    return getattr(sys, "frozen", False)


def get_bundle_dir() -> Path:
    """
    Directory holding read-only assets bundled with the executable.
    Frozen: the PyInstaller extraction dir. Source: the ``app/`` package dir.
    """
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
    return Path(__file__).resolve().parent


def get_executable_dir() -> Path:
    """
    Directory containing the running executable. Tauri places every
    ``externalBin`` next to the main app binary, so sibling sidecars
    (such as the portable scanner) are found relative to this.
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


# ==============================
# Cross-platform path normalization
# ==============================
_WINDOWS_DRIVE_ONLY = re.compile(r"^[A-Za-z]:$")


def normalize_target_path(raw: str) -> str:
    """
    Turn user/UI-supplied path text into something the scanner can walk.

    - Undoes shell-style backslash escapes ("/media/My\\ USB" -> "/media/My USB")
    - Expands ``~``
    - Promotes a bare Windows drive spec to its root ("D:" -> "D:\\")
    - Strips trailing separators without destroying roots ("/" , "D:\\")
    """
    if raw is None:
        return ""

    path = raw.strip().strip('"').strip("'")
    if not path:
        return ""

    # Shell-escaped spaces arrive verbatim when users paste from a terminal.
    path = path.replace("\\ ", " ")
    path = os.path.expanduser(path)

    # "D:" means "current dir on D:" to Windows APIs — almost never intended.
    if _WINDOWS_DRIVE_ONLY.match(path):
        return path + os.sep if os.name == "nt" else path + "\\"

    # Preserve filesystem roots and drive roots; trim everything else.
    stripped = path.rstrip("/\\")
    if not stripped or _WINDOWS_DRIVE_ONLY.match(stripped):
        return path
    return stripped


def path_basename(path: str) -> str:
    """
    Last path component, tolerant of the *other* platform's separator.
    Log rows written on Windows are viewed on Linux and vice versa.
    """
    if not path:
        return ""
    return re.split(r"[/\\]", path.rstrip("/\\"))[-1] or path


# ==============================
# Scan target safety
# ==============================
def _protected_roots() -> set:
    """Directories that must never be recursively scanned + quarantined."""
    roots = {Path(os.sep).resolve()}

    try:
        home = Path.home().resolve()
        roots.add(home)
        # Common top-level user dirs — a stray scan here would quarantine
        # documents in place, and users do paste these by mistake.
        for child in ("Documents", "Desktop", "Downloads", "Pictures", "Music", "Videos"):
            roots.add(home / child)
    except (RuntimeError, OSError):
        pass

    system = platform.system()
    if system == "Windows":
        for env in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "SystemDrive"):
            value = os.environ.get(env)
            if value:
                candidate = value if not _WINDOWS_DRIVE_ONLY.match(value) else value + "\\"
                try:
                    roots.add(Path(candidate).resolve())
                except OSError:
                    pass
    else:
        # Shared POSIX system directories. macOS has /usr, /etc, /var and
        # friends just like Linux does, so these must be protected on both —
        # listing only /System and /Library left a Mac user able to scan (and
        # quarantine inside) /usr. On macOS /etc and /var are symlinks into
        # /private, which resolve() normalizes on both sides of the compare.
        roots.update({
            Path("/usr"), Path("/etc"), Path("/var"), Path("/opt"),
            Path("/bin"), Path("/sbin"), Path("/lib"), Path("/tmp"),
        })

        if system == "Darwin":
            roots.update({
                Path("/System"), Path("/Library"), Path("/Applications"),
                Path("/Users"), Path("/Volumes"), Path("/private"), Path("/cores"),
            })
        else:
            roots.update({
                Path("/boot"), Path("/home"), Path("/proc"), Path("/sys"),
                Path("/dev"), Path("/run"), Path("/srv"), Path("/mnt"),
            })

    return roots


def check_scan_target(path: str) -> str | None:
    """
    Return a human-readable refusal reason if this path is unsafe to scan,
    or None when the target is acceptable.

    Scanning auto-quarantines, which *moves and encrypts* matched files.
    Pointing that at a system or home root is data loss, not security.
    """
    if not path:
        return "No path supplied."

    try:
        target = Path(path).resolve()
    except (OSError, ValueError):
        return f"Path could not be resolved: {path}"

    if not target.exists():
        return f"Path does not exist: {target}"
    if not target.is_dir():
        return f"Not a directory: {target}"

    for protected in _protected_roots():
        try:
            if target == protected.resolve():
                return (
                    f"Refusing to scan protected location: {target}. "
                    "Scanning quarantines matched files — point this at a "
                    "removable drive or a specific subfolder instead."
                )
        except OSError:
            continue

    return None
