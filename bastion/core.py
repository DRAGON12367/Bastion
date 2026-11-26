"""Paths, settings, the event log, and starting with Windows."""
import ctypes
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import winreg
from pathlib import Path

VERSION = "1.1.0"
NO_WINDOW = 0x08000000
FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(sys.executable).parent if FROZEN else Path(__file__).resolve().parent.parent
SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
DATA = Path(os.environ.get("BASTION_DATA") or Path(os.environ["LOCALAPPDATA"]) / "Bastion")
DATA.mkdir(parents=True, exist_ok=True)

INFO, LOW, MEDIUM, HIGH, CRITICAL = range(5)
LEVELS = ["Info", "Low", "Medium", "High", "Critical"]

DEFAULTS = {
    "auto_respond": True,      # quarantine known malware; suspend an unsigned program caught acting like ransomware
    "intel_updates": True,     # download public block lists (nothing about this PC is sent)
    "ai": True,                # let the local model read alerts and learn this PC's habits (nothing leaves the PC)
    "ai_model": "",            # empty: pick one that is installed
    "notify_level": HIGH,
    "welcomed": False,         # the first-run explanation was shown
    "watch_browsing": True,    # check sites opened in this PC's browsers against phishing lists, on this PC only
    "usage_ping": False,       # OFF unless the owner turns it on: send an anonymous random id + version to the author's counter
    "install_id": "",          # a random id made on this PC; only ever sent if usage_ping is on
    "stopped_by_user": False,  # Exit was chosen: the keep-alive task must not bring it back
    "allow": [],               # paths or sha256 the user trusts
}


class Settings:
    def __init__(self, path=None):
        self.path = Path(path or DATA / "settings.json")
        self._d = dict(DEFAULTS)
        self._lock = threading.Lock()
        try:
            d = json.loads(self.path.read_text("utf8"))
            self._d.update({k: v for k, v in d.items() if k in DEFAULTS and type(v) is type(DEFAULTS[k])})      # a damaged file must not break the guard
        except (OSError, ValueError, AttributeError):
            pass

    def __getitem__(self, k):
        return self._d[k]

    def __setitem__(self, k, v):
        with self._lock:
            self._d[k] = v
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._d, indent=1), "utf8")
            os.replace(tmp, self.path)

    def allowed(self, *keys):
        allow = {str(a).lower() for a in self._d["allow"]}
        return any(k and str(k).lower() in allow for k in keys)

    def allow(self, key):
        if key and not self.allowed(key):
            self["allow"] = self._d["allow"] + [str(key)]


class EventLog:
    """Every alert, kept on disk. The same alert is not repeated within `quiet` seconds."""

    def __init__(self, path=None, quiet=900):
        self._db = sqlite3.connect(str(path or DATA / "events.db"), check_same_thread=False)
        self._lock = threading.Lock()
        self._recent, self._quiet = {}, quiet
        self.listeners = []
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS ev(id INTEGER PRIMARY KEY, at REAL, level INT, source TEXT, title TEXT, detail TEXT, target TEXT)")
            self._db.execute("DELETE FROM ev WHERE at < ?", (time.time() - 90 * 86400,))
            self._db.commit()

    def add(self, level, source, title, detail="", target=""):
        now = time.time()
        key = (source, title, target or detail)
        with self._lock:
            if level > INFO and now - self._recent.get(key, 0) < self._quiet:
                return None
            self._recent[key] = now
            if len(self._recent) > 4000:
                self._recent = {k: t for k, t in self._recent.items() if now - t < self._quiet}
            cur = self._db.execute("INSERT INTO ev(at,level,source,title,detail,target) VALUES(?,?,?,?,?,?)",
                                   (now, level, source, title, detail[:1500], str(target)))
            self._db.commit()
            row = (cur.lastrowid, now, level, source, title, detail, str(target))
        for fn in list(self.listeners):
            fn(row)
        return row

    def latest(self, n=300, min_level=INFO):
        with self._lock:
            return self._db.execute("SELECT id,at,level,source,title,detail,target FROM ev WHERE level>=? ORDER BY id DESC LIMIT ?", (min_level, n)).fetchall()

    def count_since(self, seconds, min_level):
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM ev WHERE at>? AND level>=?", (time.time() - seconds, min_level)).fetchone()[0]


def known_folder(name, fallback):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
            return Path(os.path.expandvars(winreg.QueryValueEx(k, name)[0]))
    except OSError:
        return Path.home() / fallback


def folders():
    out = {
        "Downloads": known_folder("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
        "Desktop": known_folder("Desktop", "Desktop"),
        "Documents": known_folder("Personal", "Documents"),
        "Pictures": known_folder("My Pictures", "Pictures"),
        "Startup": known_folder("Startup", r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
        "Temp": Path(os.environ.get("TEMP", Path.home() / "AppData/Local/Temp")),
    }
    return {k: v for k, v in out.items() if v.is_dir()}


def run(args, timeout=60):
    """(exit code, output) of a console program, without a window. A bare name means Windows' own copy: never whatever else is called that."""
    if not os.path.dirname(args[0]):
        places = [os.path.join(SYSTEM32, args[0]), os.path.join(SYSTEM32, "WindowsPowerShell", "v1.0", args[0])]
        found = [p + e for p in places for e in ("", ".exe") if os.path.isfile(p + e)]
        if not found:
            return -1, args[0] + " is not part of this Windows"
        args = [found[0], *args[1:]]
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW, cwd=SYSTEM32)
        return p.returncode, (p.stdout + p.stderr).decode("utf8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def powershell(script, timeout=60):
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def quoted(s):
    """For PowerShell, whatever the user is called (O'Brien)."""
    return "'" + str(s).replace("'", "''") + "'"


def playing():
    """A full-screen game, film or presentation is in front: heavy work waits."""
    state = ctypes.c_int()
    return ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(state)) == 0 and state.value in (2, 3, 4)


def memory_short(want):
    """Less free than `want`, or than a share of it on small PCs."""
    import psutil
    m = psutil.virtual_memory()
    return m.available < min(want, m.total * 0.2)


def is_admin():
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


# ------------------------------------------------------------------ starting with Windows (this user only, no admin)
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
TASK = "Bastion keep-alive"


def launch_command():
    if FROZEN:
        return f'"{sys.executable}" --tray'
    pyw = Path(sys.executable).with_name("pythonw.exe")
    return f'"{pyw if pyw.exists() else sys.executable}" "{ROOT / "main.py"}" --tray'


def autostart_on():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            return winreg.QueryValueEx(k, "Bastion")[0] == launch_command()
    except OSError:
        return False


def set_autostart(on):
    """Run key starts it at sign-in; a task looks every 2 minutes and starts it again if it was closed by anything but Exit."""
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
        if on:
            winreg.SetValueEx(k, "Bastion", 0, winreg.REG_SZ, launch_command())
        else:
            try:
                winreg.DeleteValue(k, "Bastion")
            except OSError:
                pass
    if on:
        exe, args = launch_command()[1:].split('" ', 1)
        q = quoted
        # schtasks' own defaults skip battery power and end whatever the task started after 72 hours; a guard needs neither
        return powershell("$ErrorActionPreference='Stop'; "
                          f"$a=New-ScheduledTaskAction -Execute {q(exe)} -Argument {q(args + ' --keepalive')}; "
                          "$t=New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2); "
                          "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable "
                          "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Priority 5; "
                          f"Register-ScheduledTask -TaskName {q(TASK)} -Action $a -Trigger $t -Settings $s -Force | Out-Null")
    return run(["schtasks", "/delete", "/f", "/tn", TASK])


def remove_traces():
    """For uninstalling: automatic start, bait files and (kept on purpose: quarantine) nothing the user might still want."""
    set_autostart(False)
    for d in folders().values():
        for p in d.glob("~bastion-guard-do-not-delete.*"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x80)
                p.unlink()
            except OSError:
                pass
