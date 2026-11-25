"""The 24/7 watchers. Each runs in its own thread and is restarted if it fails."""
import base64
import ctypes
import hashlib
import ipaddress
import json
import os
import queue
import re
import string
import threading
import time
import winreg
from collections import deque
from ctypes import wintypes
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import ai, engine as E, scanner, telemetry
from .core import CRITICAL, DATA, HIGH, INFO, LOW, MEDIUM, folders, memory_short, playing, powershell, run

WINDIR = os.environ.get("SystemRoot", r"C:\Windows").lower()
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
                "taskhostw.exe", "dwm.exe", "explorer.exe", "conhost.exe", "rundll32.exe", "dllhost.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
# (program, what its command line looks like, level, meaning). Only tested against that program's own command line.
COMMANDS = [(n, re.compile(rx, re.I), lvl, why) for n, rx, lvl, why in [
    ("vssadmin.exe", r"delete\s+shadows|resize\s+shadowstorage", CRITICAL, "deleting Windows recovery copies (what ransomware does first)"),
    ("wmic.exe", r"shadowcopy\s+delete", CRITICAL, "deleting Windows recovery copies"),
    ("wbadmin.exe", r"delete\s+(catalog|systemstatebackup)", CRITICAL, "deleting Windows backups"),
    ("bcdedit.exe", r"recoveryenabled\s+no|ignoreallfailures", CRITICAL, "switching off Windows recovery"),
    ("powershell.exe", r"set-mppreference.*-disable\w+\s+(\$true|1)", CRITICAL, "switching off Defender"),
    ("pwsh.exe", r"set-mppreference.*-disable\w+\s+(\$true|1)", CRITICAL, "switching off Defender"),
    ("powershell.exe", r"add-mppreference.*-exclusion", HIGH, "telling Defender to ignore something"),
    ("powershell.exe", r"(downloadstring|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|frombase64string).*(\biex\b|invoke-expression)|(\biex\b|invoke-expression).*(downloadstring|invoke-webrequest|\biwr\b|frombase64string)", HIGH, "running code straight from the internet or hidden text"),
    ("mshta.exe", r"https?:|javascript:|vbscript:", HIGH, "running a script from the web"),
    ("regsvr32.exe", r"/i:\s*https?:|scrobj", HIGH, "loading a script from the web"),
    ("rundll32.exe", r"javascript:|vbscript:", HIGH, "running a hidden script"),
    ("certutil.exe", r"-urlcache|-verifyctl.*http", HIGH, "downloading with a Windows tool"),
    ("bitsadmin.exe", r"/transfer.*http", MEDIUM, "downloading with a Windows tool"),
    ("netsh.exe", r"advfirewall\s+set\s+\w+\s+state\s+off", HIGH, "switching off the firewall"),
    ("reg.exe", r"save\s+hk(lm|ey_local_machine)\\(sam|security|system)\b", CRITICAL, "copying stored Windows passwords"),
    ("rundll32.exe", r"comsvcs.*minidump", CRITICAL, "copying passwords from Windows' memory"),
    ("reg.exe", r"add.*disable(antispyware|realtimemonitoring|behaviormonitoring)", CRITICAL, "switching off Defender"),
    ("sc.exe", r"(stop|config|delete)\s+(windefend|wscsvc|mpssvc|securityhealthservice)", CRITICAL, "switching off Windows security"),
    ("reg.exe", r"add.*(ms-settings|mscfile)\\+shell\\+open\\+command", CRITICAL, "sneaking past the administrator prompt"),
    ("fsutil.exe", r"usn\s+deletejournal", HIGH, "wiping traces of file changes"),
    ("netsh.exe", r"wlan\s+show\s+profile.*key=clear", HIGH, "reading saved Wi-Fi passwords"),
    ("schtasks.exe", r"/create.*(powershell.*(-e|hidden)|mshta|\\temp\\|\\users\\public\\)", HIGH, "hiding a program in scheduled tasks"),
    ("net.exe", r"user\s+\S+\s+\S*\s*/add|localgroup\s+administrators\s+.*/add", HIGH, "adding a Windows user or administrator"),
    ("certutil.exe", r"-decode(hex)?\b", MEDIUM, "unpacking a hidden file with a Windows tool"),
    ("curl.exe", r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot", HIGH, "sending data to a chat service"),
    ("powershell.exe", r"-w(indowstyle)?\s+h\w*\s.*-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{60,}|-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{60,}.*-w(indowstyle)?\s+h", HIGH, "running a hidden, encoded command"),
    ("wevtutil.exe", r"\bcl\b|clear-log", HIGH, "wiping the Windows event log"),
]]


BROWSERS = {"msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe"}
JAVA = {"java.exe", "javaw.exe", "javaws.exe", "jp2launcher.exe", "jweblauncher.exe"}
READERS = {"acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "winrar.exe", "7zfm.exe", "hh.exe"}
# Where a person (or a booby-trapped page or document) starts things from. Developer tools and terminals are not in this list.
LURES = BROWSERS | OFFICE | READERS | JAVA | {"explorer.exe"}
FETCH = re.compile(r"https?:|\\\\[\w.-]+@(ssl|\d+)|downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|\b(iwr|irm)\b|start-bitstransfer", re.I)
EXECUTE = re.compile(r"\biex\b|invoke-expression|start-process|\bsaps\b|\|\s*(cmd|powershell)|&&?\s*(start|call|\S+\.(exe|bat|cmd|js|vbs|hta|msi))|frombase64string|\[scriptblock\]|-w(indowstyle)?\s+h", re.I)
# .NET helper tools that have no business on the internet: stealers and RATs hide inside them.
HOSTS = {"regasm.exe", "regsvcs.exe", "installutil.exe", "vbc.exe", "aspnet_compiler.exe", "addinprocess.exe", "addinprocess32.exe", "jsc.exe", "cvtres.exe", "applaunch.exe"}
NET_SCRIPT = {"mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "cmstp.exe"}
TOOLS = SHELLS | HOSTS | {"pwsh.exe", "msiexec.exe", "curl.exe"}
# Remote-control programs: real products, but also what phone scammers and intruders install.
REMOTE = {"anydesk.exe": "AnyDesk", "teamviewer.exe": "TeamViewer", "teamviewer_service.exe": "TeamViewer", "rustdesk.exe": "RustDesk", "client32.exe": "NetSupport",
          "screenconnect.clientservice.exe": "ScreenConnect", "screenconnect.windowsclient.exe": "ScreenConnect", "ateraagent.exe": "Atera", "srserver.exe": "Splashtop",
          "sragent.exe": "Splashtop", "winvnc.exe": "VNC", "tvnserver.exe": "TightVNC", "vncserver.exe": "VNC", "supremo.exe": "Supremo", "ammyy_admin.exe": "Ammyy Admin",
          "aa_v3.exe": "Ammyy Admin", "ultraviewer_desktop.exe": "UltraViewer", "meshagent.exe": "MeshCentral", "remoting_host.exe": "Chrome Remote Desktop",
          "dwagent.exe": "DWService", "dwagsvc.exe": "DWService", "logmein.exe": "LogMeIn", "g2comm.exe": "GoToMyPC", "ngrok.exe": "ngrok tunnel", "zohoursservice.exe": "Zoho Assist"}


def plain(cmd):
    """The command line with carets, backticks and base64 wrapping taken off."""
    cmd = cmd or ""
    out = cmd.replace("^", "").replace("`", "")
    m = re.search(r"-e(?:nc|ncodedcommand|c)?\s+\"?([A-Za-z0-9+/=]{24,})", cmd, re.I)
    if m:
        try:
            out += " " + base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16-le", "ignore").replace("`", "")
        except ValueError:
            pass
    return out


def lured(name, cmd, parent):
    """A page, document or 'paste this to prove you are human' trick making Windows fetch something and run it."""
    name, parent = (name or "").lower(), (parent or "").lower()
    if parent not in LURES or name not in TOOLS or "chrome-extension://" in (cmd or "") or "nativemessaging" in (cmd or "").lower():
        return False
    text = plain(cmd)
    if not FETCH.search(text):
        return False
    return name in ("mshta.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe") or bool(EXECUTE.search(text))


def public_ip(ip):
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False


def rat_score(odd_port, hidden, autostart, recent, concealed):
    """How much an unsigned program in a user folder, connected to the internet, behaves like a remote-access trojan. 70 alerts, 95 freezes."""
    return 20 + 25 * odd_port + 20 * hidden + 25 * autostart + 15 * recent + 20 * concealed


# ---- looking inside Windows, read-only
class _MBI(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("abase", ctypes.c_void_p), ("aprot", wintypes.DWORD), ("part", wintypes.DWORD), ("size", ctypes.c_size_t),
                ("state", wintypes.DWORD), ("prot", wintypes.DWORD), ("type", wintypes.DWORD)]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(_MBI), ctypes.c_size_t]
_k32.VirtualQueryEx.restype = ctypes.c_size_t
_k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
_k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.c_void_p] * 4


def injected(pid):
    """Address of a whole program hidden in another one's private, runnable memory, or None."""
    h = _k32.OpenProcess(0x0410, False, pid)
    if not h:
        return None
    try:
        m, addr, buf = _MBI(), 0, ctypes.create_string_buffer(1024)
        while _k32.VirtualQueryEx(h, addr, ctypes.byref(m), ctypes.sizeof(m)) and m.size:
            if m.state == 0x1000 and m.type == 0x20000 and m.prot & 0xF0 and not m.prot & 0x100 and m.size >= 4096:
                if _k32.ReadProcessMemory(h, m.base, buf, 1024, None) and buf.raw[:2] == b"MZ":
                    pe = int.from_bytes(buf.raw[60:64], "little")
                    if pe < 1000 and buf.raw[pe:pe + 4] == b"PE\0\0":
                        return m.base
            addr = (m.base or 0) + m.size
            if addr >= 0x7FFFFFFF0000:
                break
    finally:
        _k32.CloseHandle(h)
    return None


def hidden_pids():
    """Running processes that answer when asked directly but are missing from Windows' own list."""
    before = set(psutil.pids())
    found = []
    for pid in range(4, 65536 * 2, 4):
        if pid in before:
            continue
        h = _k32.OpenProcess(0x1000, False, pid)
        if h:
            t = [ctypes.c_ulonglong() for _ in range(4)]
            if _k32.GetProcessTimes(h, *[ctypes.byref(x) for x in t]) and t[1].value == 0:     # no exit time: still running
                found.append(pid)
            _k32.CloseHandle(h)
    return set(found) - set(psutil.pids())


def loaded_drivers():
    size = wintypes.ULONG(1 << 20)
    buf = ctypes.create_string_buffer(size.value)
    if ctypes.windll.ntdll.NtQuerySystemInformation(11, buf, size, ctypes.byref(size)):
        raise OSError("could not list drivers")
    n = int.from_bytes(buf.raw[:4], "little")
    names = (buf.raw[8 + i * 296 + 40:8 + (i + 1) * 296].split(b"\0")[0].decode("mbcs", "replace") for i in range(n))
    return [driver_path(x) for x in names if x]


def driver_path(p):
    p = p.strip('"')
    low = p.lower()
    if low.startswith("\\??\\"):
        return p[4:]
    if low.startswith("\\systemroot\\"):
        return WINDIR + p[11:]
    if low.startswith("\\windows\\"):
        return WINDIR + p[8:]
    return WINDIR + "\\" + p if low.startswith("system32") else os.path.expandvars(p)


# Windows' own processes are only ever started by these.
PARENTS = {"svchost.exe": {"services.exe", "msmpeng.exe", "svchost.exe"}, "lsass.exe": {"wininit.exe"}, "services.exe": {"wininit.exe"}, "taskhostw.exe": {"svchost.exe"}}
NO_PLACE = re.compile(r"\\\$recycle\.bin\\|\\users\\public\\|\\windows\\fonts\\|\\perflogs\\|\\windows\\(debug|tracing|help)\\|\\programdata\\[^\\]+\.exe$|\\appdata\\(roaming|local)\\[^\\]+\.exe$", re.I)
# Windows libraries that malware likes to fake next to an honest program, which then loads the fake.
SIDELOAD = {"version.dll", "dbghelp.dll", "wininet.dll", "userenv.dll", "cryptsp.dll", "cryptbase.dll", "dwmapi.dll", "uxtheme.dll", "wtsapi32.dll", "propsys.dll", "profapi.dll", "msimg32.dll", "secur32.dll", "winhttp.dll"}


def user_writable(path):
    p = str(path).lower()
    home = str(Path.home()).lower()
    return p.startswith((home, os.environ.get("ProgramData", r"c:\programdata").lower(), WINDIR + r"\temp", r"c:\users\public"))


def judge_process(name, exe, cmd, parent):
    """(level, title) findings from names and command line alone."""
    name, parent, low = (name or "").lower(), (parent or "").lower(), (exe or "").lower()
    out = []
    raw, cmd = cmd or "", plain(cmd)
    if name in SYSTEM_NAMES and low and not low.startswith(WINDIR + "\\"):
        out.append((CRITICAL, f"{name} is running from the wrong place (a disguise)"))
    if parent and name in PARENTS and parent not in PARENTS[name]:
        out.append((HIGH, f"{name} was started by {parent}, which Windows never does"))
    if low and NO_PLACE.search(low):
        out.append((HIGH, f"{name} is running from a place programs don't belong"))
    if parent in OFFICE and name in SHELLS:
        out.append((HIGH, f"a document opened {name}"))
    if parent in BROWSERS and name in (SHELLS | {"pwsh.exe"}) - {"rundll32.exe"} and "chrome-extension://" not in raw and "nativemessaging" not in raw.lower():
        out.append((HIGH, f"a web page or browser add-on opened {name} (drive-by)"))
    if parent in JAVA and name in (SHELLS | {"pwsh.exe"}) - {"rundll32.exe", "cmd.exe"}:
        out.append((HIGH, f"a Java program opened {name}"))
    if name in JAVA and re.search(r"https?://\S+\.(jar|jnlp)|\.jnlp\b", raw, re.I):
        out.append((HIGH, "Java is running a program straight from the web"))
    for n, rx, lvl, why in COMMANDS:
        if n == name and rx.search(cmd or ""):
            out.append((lvl, why))
    return out


class Guard(threading.Thread):
    label, every = "Guard", 5.0

    def __init__(self, ctx):
        super().__init__(daemon=True, name=self.label)
        self.ctx, self.state, self.beat, self.fails = ctx, "starting", 0.0, 0

    def setup(self):
        pass

    def step(self):
        raise NotImplementedError

    def status(self):
        return "on"

    def run(self):
        ready = False
        while not self.ctx.stop.is_set():
            try:
                if not ready:
                    self.setup()
                    ready = True
                self.step()
                self.state, self.beat, self.fails = self.status(), time.time(), 0
            except Exception as e:      # a guard must never die quietly
                self.fails += 1
                self.state = "error: " + str(e)[:120]
                self.ctx.log.add(LOW, self.label, "Guard error (restarting)", repr(e))
            self.ctx.stop.wait(min(60.0, self.every * (1 + self.fails)))
        self.teardown()

    def teardown(self):
        pass


class FileGuard(Guard):
    """New and changed files where things arrive: judged by Bastion's rules, then by Defender when anything looks off."""
    label, every = "Files", 0.1

    def setup(self):
        if getattr(self, "obs", None):
            self.teardown()
        self.q, self.queued = queue.Queue(20000), set()
        self.seen = {}
        self.obs = Observer()
        guard = self

        class H(FileSystemEventHandler):
            def on_created(self, ev): guard.offer(ev.src_path, ev.is_directory)
            def on_modified(self, ev): guard.offer(ev.src_path, ev.is_directory)
            def on_moved(self, ev):
                guard.offer(ev.dest_path, ev.is_directory)
                guard.ctx.ransom.renamed(ev.src_path, ev.dest_path)

        f = folders()
        for n in ("Downloads", "Desktop", "Startup", "Temp", "Documents", "Pictures"):
            if n in f:
                self.obs.schedule(H(), str(f[n]), recursive=True)
        self.obs.start()
        self.hands = [threading.Thread(target=self.hand, daemon=True, name="file check") for _ in range(2)]
        for t in self.hands:
            t.start()

    def hand(self):
        while not self.ctx.stop.is_set() and self.obs is not None:
            try:
                self.one()
            except Exception as e:
                self.ctx.log.add(LOW, self.label, "A file could not be checked", repr(e))

    def offer(self, path, is_dir):
        if is_dir:
            return
        self.ctx.ransom.touched(path)
        p = str(path).lower()
        if str(DATA).lower() in p:
            return
        ext = os.path.splitext(p)[1]
        if ext in E.DEV_EXT and ("\\documents\\" in p or scanner.LIBRARIES.search(p)):
            return
        if ext not in E.RISKY and os.path.splitext(os.path.splitext(p)[0])[1] not in E.DECOY:
            return
        if path in self.queued:         # still waiting: it will be looked at in its final state anyway
            return
        try:
            self.queued.add(path)
            self.q.put_nowait((time.time(), path))
        except queue.Full:
            self.queued.discard(path)
            self.ctx.log.add(LOW, self.label, "Too many new files at once; some were left to Defender")

    def step(self):
        if not self.obs.is_alive():
            raise RuntimeError("file watcher stopped")
        self.one()

    def one(self):
        try:
            at, path = self.q.get(timeout=1.0)
        except queue.Empty:
            return
        wait = 1.5 - (time.time() - at)
        if wait > 0:
            self.ctx.stop.wait(wait)      # let it finish being written
        self.queued.discard(path)
        try:
            st = os.stat(path)
        except OSError:
            return
        key = (st.st_size, st.st_mtime_ns)
        if self.seen.get(path) == key:
            return
        self.seen[path] = key
        if len(self.seen) > 8000:
            self.seen.clear()
        self.ctx.examine(path, "Files", deep=E.from_internet(path))

    def teardown(self):
        try:
            self.obs.stop()
        except Exception:
            pass
        self.obs = None


class ProcessGuard(Guard):
    label, every = "Programs", 0.25

    def setup(self):
        self.known, self.sides = set(psutil.pids()), set()

    def step(self):
        now = set(psutil.pids())
        new, self.known = now - self.known, now
        for pid in new:
            try:
                p = psutil.Process(pid)
                with p.oneshot():
                    name, exe = p.name(), p.exe()
                    cmd = " ".join(p.cmdline())
                    par = p.parent()
                    parent = par.name() if par else ""
            except (psutil.Error, OSError):
                continue
            if self.ctx.settings.allowed(exe):
                continue
            for level, why in judge_process(name, exe, cmd, parent):
                self.ctx.log.add(level, self.label, why, f"{exe}\nstarted by {parent}\n{cmd[:400]}", exe)
                if level == CRITICAL:
                    self.ctx.restrain(p, why)
            bits = self.ctx.habits.see(name, exe, cmd, parent) if self.ctx.settings["ai"] else None
            if bits and (name.lower() in TOOLS or user_writable(exe) and not E.signed(exe)):
                self.ctx.log.add(MEDIUM, "Habits", f"Unusual for this PC: {parent or 'an unknown program'} started {name}", f"{exe}\n{cmd[:400]}", exe)
            if lured(name, cmd, parent) and not self.ctx.settings.allowed(cmd[:300]):
                why = "fetching and running something from the web (fake CAPTCHA or drive-by)"
                self.ctx.log.add(CRITICAL, self.label, f"{parent} made {name} download and run something", f"{exe}\n{cmd[:400]}", cmd[:300])
                self.ctx.restrain(p, why, tool=True)
            if name.lower() in JAVA:
                for jar in re.findall(r"[A-Za-z]:\\[^\"*?<>|]+?\.jar\b", cmd)[:3]:
                    if re.search(r"\\(downloads|temp|desktop)\\", jar, re.I) and os.path.isfile(jar):
                        self.ctx.examine(jar, self.label, deep=True)
            low = exe.lower()
            if user_writable(exe) and not self._temp(low):
                self.sideload(exe)
            if user_writable(exe) and (self._temp(low) or "\\downloads\\" in low):
                self.ctx.examine(exe, self.label, running=p)

    def sideload(self, exe):
        """A signed program in a user folder with an unsigned stand-in for a Windows library beside it."""
        d = os.path.dirname(exe)
        if d in self.sides:
            return
        self.sides.add(d)
        try:
            hits = [f for f in os.listdir(d) if f.lower() in SIDELOAD]
            for f in hits[:3]:
                dll = os.path.join(d, f)
                if E.signed(exe) and not E.signed(dll) and not E.cataloged(dll) and not self.ctx.settings.allowed(dll):
                    self.ctx.log.add(MEDIUM, self.label, f"{os.path.basename(exe)} loads an unsigned stand-in for {f}", f"{dll}\nGame mods do this too; malware does it to hide behind an honest program.", dll)
                    self.ctx.examine(dll, self.label, deep=True)
        except OSError:
            pass

    @staticmethod
    def _temp(low):
        return low.startswith(os.environ.get("TEMP", "~").lower())


class StartupGuard(Guard):
    """Anything new that arranges to start by itself, compared with how this PC was when Bastion was first run."""
    label, every = "Startup", 45.0
    RUNS = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    BASE = r"Software\Microsoft\Windows\CurrentVersion"

    def setup(self):
        self.file = DATA / "startup_baseline.json"
        try:
            self.base = json.loads(self.file.read_text("utf8"))
        except (OSError, ValueError):
            self.base = self.snapshot()
            self._save()
            self.ctx.log.add(INFO, self.label, "Startup baseline recorded", f"{len(self.base)} entries")
        if self.base.get("Meta|version") != "2":       # places this version watches that the old one did not
            kinds = {k.split("|")[0] for k in self.base}
            new = {k: v for k, v in self.snapshot().items() if k.split("|")[0] not in kinds}
            self.base.update(new)
            self._save()
            self.ctx.log.add(INFO, self.label, "More start-up hiding places are now watched", f"{len(new)} existing entries noted")

    def _save(self):
        self.file.write_text(json.dumps(self.base), "utf8")

    @staticmethod
    def _values(hive, path, view=0):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        return
                    yield n, str(v)
                    i += 1
        except OSError:
            return

    @staticmethod
    def _subkeys(hive, path):
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        yield winreg.EnumKey(k, i)
                    except OSError:
                        return
                    i += 1
        except OSError:
            return

    def snapshot(self):
        s = {}
        for hive, tag in self.RUNS:
            for view, v in ((winreg.KEY_WOW64_64KEY, ""), (winreg.KEY_WOW64_32KEY, "32")):
                for sub in ("Run", "RunOnce"):
                    for n, val in self._values(hive, self.BASE + "\\" + sub, view):
                        s[f"Run|{tag}{v}\\{sub}\\{n}"] = val
        for n, val in self._values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"):
            if n.lower() in ("shell", "userinit"):
                s["Sign-in|" + n] = val
        ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        for name in self._subkeys(winreg.HKEY_LOCAL_MACHINE, ifeo):
            for n, val in self._values(winreg.HKEY_LOCAL_MACHINE, ifeo + "\\" + name):
                if n.lower() == "debugger":
                    s["Hijack|" + name] = val
        for d in (folders().get("Startup"), Path(os.environ.get("ProgramData", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"):
            if d and d.is_dir():
                for f in d.iterdir():
                    if f.name.lower() != "desktop.ini":
                        s["Folder|" + str(f)] = str(f.stat().st_mtime_ns)
        tree = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
        for name in self._subkeys(winreg.HKEY_LOCAL_MACHINE, tree):
            if name != "Microsoft":
                s["Task|" + name] = ""
        svc = r"SYSTEM\CurrentControlSet\Services"
        for name in self._subkeys(winreg.HKEY_LOCAL_MACHINE, svc):
            if re.search(r"_[0-9a-f]{4,}$", name):      # per-user copies get a new name each sign-in
                continue
            for n, val in self._values(winreg.HKEY_LOCAL_MACHINE, svc + "\\" + name):
                if n == "ImagePath":
                    s["Service|" + name] = val
        s["Meta|version"] = "2"
        LM, CU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
        nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
        for hive, path, names in (
                (LM, nt + r"\Windows", ("appinit_dlls", "loadappinit_dlls")), (CU, nt + r"\Windows", ("load", "run")),
                (LM, lsa, ("security packages", "notification packages", "authentication packages")),
                (LM, r"SYSTEM\CurrentControlSet\Control\Session Manager", ("bootexecute", "setupexecute")),
                (CU, "Environment", ("userinitmprlogonscript", "cor_profiler", "cor_profiler_path", "coreclr_profiler", "java_tool_options", "_java_options"))):
            for n, val in self._values(hive, path):
                if n.lower() in names:
                    s[f"Deep|{path}\\{n}"] = val
        for n, val in self._values(LM, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"):
            s["Deep|AppCertDlls\\" + n] = val
        for name in self._subkeys(LM, nt + r"\SilentProcessExit"):
            for n, val in self._values(LM, nt + "\\SilentProcessExit\\" + name):
                if n.lower() == "monitorprocess":
                    s["Deep|SilentProcessExit\\" + name] = val
        for name in self._subkeys(CU, r"Software\Classes\CLSID"):      # per-user hijacks of Windows components
            for n, val in self._values(CU, rf"Software\Classes\CLSID\{name}\InprocServer32"):
                if n == "":
                    s["Component|" + name] = val
        for cls in ("ms-settings", "mscfile", "exefile"):               # silent administrator tricks
            for n, val in self._values(CU, rf"Software\Classes\{cls}\shell\open\command"):
                s[f"Deep|{cls}\\{n}"] = val
        for hive, tag in self.RUNS:
            for b in (r"Microsoft\Edge", r"Google\Chrome"):
                for n, val in self._values(hive, rf"SOFTWARE\Policies\{b}\ExtensionInstallForcelist"):
                    s[f"Extension|{tag}\\{b}\\{n}"] = val
            for name in self._subkeys(hive, r"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"):
                s[f"Certificate|{tag}\\{name}"] = ""
        for n, val in self._values(CU, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"):
            if n.lower() in ("proxyserver", "autoconfigurl"):
                s["Proxy|" + n] = val
        try:
            hosts = Path(WINDIR) / r"System32\drivers\etc\hosts"
            s["Hosts|file"] = hashlib.sha256(hosts.read_bytes()).hexdigest()
        except OSError:
            pass
        return s

    def step(self):
        now = self.snapshot()
        for k, v in now.items():
            if self.base.get(k) == v:
                continue
            kind, what = k.split("|", 1)
            if kind == "Meta" or kind == "Component" and E.signed(os.path.expandvars(v)):      # OneDrive and others move theirs at every update
                continue
            if kind == "Run" and what.endswith("\\Bastion") or what == "Bastion keep-alive":
                continue
            level = {"Hijack": CRITICAL, "Sign-in": CRITICAL, "Hosts": HIGH, "Task": MEDIUM, "Deep": HIGH, "Extension": HIGH, "Certificate": HIGH, "Proxy": HIGH}.get(kind, MEDIUM)
            if kind in ("Run", "Service", "Folder") and re.search(r"\\temp\\|powershell|mshta|wscript|\\users\\public\\", v, re.I):
                level = HIGH
            verb = "Changed" if k in self.base else "New"
            title = {"Run": "program starts with Windows", "Service": "Windows service", "Task": "scheduled task", "Folder": "Startup folder item",
                     "Hosts": "hosts file (redirects websites)", "Hijack": "program hijack", "Sign-in": "sign-in program",
                     "Deep": "deep Windows start-up entry", "Component": "replacement for a Windows component", "Extension": "forced browser add-on",
                     "Certificate": "trusted root certificate (can allow spying on secure sites)", "Proxy": "proxy (can redirect your browsing)"}[kind]
            self.ctx.log.add(level, self.label, f"{verb} {title}", f"{what}\n{v}", what)
        if now != self.base:
            self.base = now
            self._save()


class RansomGuard(Guard):
    """Bait files nobody should touch, and bursts of renames that add an ending to documents."""
    label, every = "Ransomware", 2.0
    NAME = "~bastion-guard-do-not-delete"
    BODY = b"This file is bait. If ransomware changes it, Bastion raises the alarm. Please leave it here.\r\n" * 40

    def __init__(self, ctx, places=None):
        super().__init__(ctx)
        self.places = places
        self.renames = deque()
        self.baits, self.poke = {}, threading.Event()
        self.lock = threading.Lock()

    def setup(self):
        places = self.places or [folders()[n] for n in ("Documents", "Pictures", "Downloads") if n in folders()]
        for d in places:
            for ext in (".docx", ".jpg"):
                p = Path(d) / (self.NAME + ext)
                self.lay(p)

    def lay(self, p):
        if not p.exists() or p.read_bytes() != self.BODY:
            ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x80)
            p.write_bytes(self.BODY)
        ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x2)
        self.baits[str(p).lower()] = p

    def touched(self, path):
        if str(path).lower() in self.baits:
            self.poke.set()

    def renamed(self, src, dst):
        a, b = os.path.basename(str(src)).lower(), os.path.basename(str(dst)).lower()
        ext = os.path.splitext(a)[1]
        # report.docx -> report.docx.locked  (not browsers' .crdownload, not editors' .bak / .tmp)
        if ext in E.DECOY and b.startswith(a + ".") and not b.endswith((".bak", ".tmp", ".old", ".crdownload", ".part")):
            now = time.time()
            with self.lock:
                self.renames.append(now)
                while self.renames and now - self.renames[0] > 10:
                    self.renames.popleft()
                n = len(self.renames)
            if n >= 20:
                with self.lock:
                    self.renames.clear()
                self.alarm(f"{n} documents renamed in 10 seconds", str(dst))

    def step(self):
        self.poke.wait(self.every)
        self.poke.clear()
        hit, changed = [], False
        for p in self.baits.values():
            try:
                if p.read_bytes() != self.BODY:
                    hit.append(p)
                    changed = True
            except FileNotFoundError:
                hit.append(p)
            except OSError:
                continue
        if hit:
            if changed or len(hit) > 1:
                self.alarm("bait files were changed or removed", str(hit[0]))
            else:       # one deleted file can be a tidy-up: say so, freeze nothing
                self.ctx.log.add(HIGH, self.label, "A bait file was deleted", f"{hit[0]}\nIt has been put back. If you removed it, that's fine.", str(hit[0]))
            for p in hit:
                try:
                    self.lay(p)
                except OSError:
                    pass

    def alarm(self, why, where):
        self.ctx.log.add(CRITICAL, self.label, "Possible ransomware", f"{why}\n{where}", where)
        self.ctx.contain(why)


class NetworkGuard(Guard):
    label, every = "Network", 10.0

    def setup(self):
        self.ports = None

    def step(self):
        listen = set()
        for c in psutil.net_connections("inet"):
            if c.status == psutil.CONN_LISTEN and c.laddr.ip not in ("127.0.0.1", "::1"):
                listen.add((self._prog(c.pid), c.laddr.port))
            if not c.raddr:
                continue
            why = self.ctx.intel.bad_ip(c.raddr.ip)
            if why:
                name = self._prog(c.pid)
                self.ctx.log.add(HIGH, self.label, f"{name} is talking to a {why}", f"{c.raddr.ip}:{c.raddr.port}", f"{name} {c.raddr.ip}")
        if self.ports is not None:
            for name, port in listen - self.ports:
                if port < 49152:
                    self.ctx.log.add(LOW, self.label, f"{name} opened port {port} to the network", "", f"{name}:{port}")
        self.ports = listen | (self.ports or set())

    @staticmethod
    def _prog(pid):
        try:
            return psutil.Process(pid).name() if pid else "System"
        except psutil.Error:
            return "a program"


class DriveGuard(Guard):
    label, every = "USB drives", 3.0

    def setup(self):
        self.have = self._drives()

    @staticmethod
    def _drives():
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        return {c for i, c in enumerate(string.ascii_uppercase) if mask >> i & 1 and ctypes.windll.kernel32.GetDriveTypeW(f"{c}:\\") == 2}

    def step(self):
        now = self._drives()
        for c in now - self.have:
            self.ctx.log.add(INFO, self.label, f"USB drive {c}: connected, checking it")
            bad = 0
            try:
                for f in Path(f"{c}:\\").iterdir():
                    if f.is_file() and (f.suffix.lower() in E.RISKY or f.name.lower() == "autorun.inf"):
                        bad += self.ctx.examine(str(f), self.label).verdict > E.CLEAN
            except OSError:
                continue
            verdict, why = E.defender_scan(f"{c}:\\", 1800)
            self.ctx.log.add(HIGH if bad or verdict == "threat" else INFO, self.label,
                             f"USB drive {c}: " + ("has suspicious files" if bad or verdict == "threat" else "looks clean" if verdict == "clean" else "Defender could not check it"), why)
        self.have = now


class _LastInput(ctypes.Structure):
    _fields_ = [("cb", wintypes.UINT), ("tick", wintypes.DWORD)]


def idle_seconds():
    li = _LastInput(ctypes.sizeof(_LastInput))
    ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li))
    return ((ctypes.windll.kernel32.GetTickCount() - li.tick) & 0xFFFFFFFF) / 1000


def scan_due(full, quick, idle):
    """Full scan weekly, quick scan daily, while nobody is using the PC; a badly overdue quick scan does not wait. Days since each last finished."""
    full, quick = (9999 if v is None else v for v in (full, quick))
    if full >= 7 and idle >= 1200:
        return "full"
    if quick >= 1 and (idle >= 300 or quick >= 3):
        return "quick"
    return None


class DefenderGuard(Guard):
    """Watches the watchman: Defender on, up to date, not tampered with. Scans on a schedule. Keeps the block lists fresh."""
    scanning, finished, asked = None, (None, None), 0.0
    # Defender's own "days since" counters also count scans that were stopped, so only its log of finished scans is believed.
    FINISHED = ("$o=@(); foreach ($n in 2,1) { $x=\"*[System[(EventID=1001)] and EventData[Data[@Name='Scan Parameters Index']='$n']]\"; "
                "try { $e=Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath $x -MaxEvents 1 -ErrorAction Stop; "
                "$o += [math]::Floor(((Get-Date)-$e.TimeCreated).TotalDays) } catch { $o += -1 } }; 'AGES ' + ($o -join ' ')")

    def setup(self):
        self.tried = time.time()        # no scan in the first hours after starting: signing in is when the PC is wanted

    def ages(self):
        """(full, quick): days since each last finished, None when Defender's log has no such scan."""
        if time.time() - self.asked > 3600:
            code, out = powershell(self.FINISHED)
            m = re.search(r"AGES (-?\d+) (-?\d+)", out)
            if not m:
                raise RuntimeError("could not read when scans finished")
            self.finished, self.asked = tuple(None if int(g) < 0 else int(g) for g in m.groups()), time.time()
        return self.finished

    def routine(self, kind):
        exe = E.defender_exe()
        if not kind or exe is None or memory_short(3e9) or playing() or self.scanning and self.scanning.is_alive() or time.time() - self.tried < 6 * 3600:
            return
        self.tried = time.time()

        def go():
            code, out = run([str(exe), "-Scan", "-ScanType", "2" if kind == "full" else "1"], 24 * 3600)
            if re.search(r"found\s+[1-9]\d*\s+threat|threat information|threat\s+:", out, re.I):
                self.ctx.log.add(CRITICAL, self.label, f"The scheduled {kind} scan found something", out[-600:].strip() + "\nOpen Windows Security > Protection history.", "scan")
            elif code == 0:
                self.ctx.log.add(INFO, self.label, f"Scheduled {kind} scan finished: no threats")
                self.asked = 0.0
            else:
                self.ctx.log.add(LOW, self.label, f"Scheduled {kind} scan did not finish; trying again later", out[-300:].strip())
        self.ctx.log.add(INFO, self.label, f"Scheduled {kind} scan started")
        self.scanning = threading.Thread(target=go, daemon=True, name="scheduled scan")
        self.scanning.start()

    label, every = "Defender", 600.0
    # Security Center says which antivirus is switched on (bits 12-15 of its state), so PCs that use another one are not told they are unprotected.
    SCRIPT = ("$av=@(Get-CimInstance -Namespace root/SecurityCenter2 AntiVirusProduct -ErrorAction SilentlyContinue | ?{(($_.productState -shr 12) -band 15) -eq 1 -and $_.displayName -notmatch 'Defender'} | %{$_.displayName}) -join ', ';"
              "$ErrorActionPreference='SilentlyContinue'; $s=Get-MpComputerStatus; $p=Get-MpPreference; @{other=\"$av\";rt=[bool]$s.RealTimeProtectionEnabled;bm=[bool]$s.BehaviorMonitorEnabled;tp=[bool]$s.IsTamperProtected;"
              "age=$s.AntivirusSignatureAge;full=$s.FullScanAge;quick=$s.QuickScanAge;np=[int]$p.EnableNetworkProtection;cfa=[int]$p.EnableControlledFolderAccess;"
              "cloud=[int]$p.CloudBlockLevel;pua=[int]$p.PUAProtection;hvci=((Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard Win32_DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning -contains 2);asr=@($p.AttackSurfaceReductionRules_Ids|?{$_}).Count}|ConvertTo-Json -Compress")

    def step(self):
        code, out = powershell(self.SCRIPT)
        m = re.search(r"\{.*\}", out, re.S)
        if code != 0 or not m:
            raise RuntimeError("could not read Defender's state")
        d = self.ctx.defender = json.loads(m.group(0))
        if self.ctx.settings["intel_updates"] and time.time() - self.ctx.intel.updated > 6 * 3600:
            self.ctx.intel.update()
        if d.get("other") and not d["rt"]:      # Windows has handed the job to another antivirus: Defender's own state means nothing then
            return
        if not d["rt"]:
            self.ctx.log.add(CRITICAL, self.label, "Defender real-time protection is OFF", "Turn it back on in Windows Security.", "rt")
        if not d["tp"]:
            self.ctx.log.add(HIGH, self.label, "Defender tamper protection is off", "", "tp")
        if d["rt"]:
            full, quick = self.ages()
            d["full"], d["quick"] = full, quick
            self.routine(scan_due(full, quick, idle_seconds()))
            if full is None or full >= 14:
                self.ctx.log.add(LOW, self.label, "No full scan has finished lately", f"{'Never, as far as the log goes' if full is None else f'{full} days ago'}. Leave the PC on and unused for a couple of hours.", "fullscan")
        if (d["age"] or 0) >= 1:
            exe = E.defender_exe()
            if exe:
                run([str(exe), "-SignatureUpdate"], 300)
        if (d["age"] or 0) >= 4:
            self.ctx.log.add(HIGH, self.label, "Defender's virus definitions are old", f"{d['age']} days", "age")


class RatGuard(Guard):
    """Remote-access trojans: hidden programs phoning home, spying through camera or microphone, code hidden inside other programs, remote-control tools."""
    label, every = "RAT", 15.0
    WEB_PORTS = {53, 80, 123, 443, 853, 993, 587, 465, 5222, 5228, 8080, 8443}

    def setup(self):
        self.told, self.sign, self.looked = set(), {}, {}

    def once(self, key):
        if key in self.told:
            return False
        self.told.add(key)
        return True

    def signed(self, exe):
        try:
            key = (exe, os.stat(exe).st_mtime_ns)
        except OSError:
            return True             # cannot be read: no claim either way
        if key not in self.sign:
            try:
                self.sign[key] = E.signed(exe) or E.cataloged(exe)
            except OSError:
                return True
        return self.sign[key]

    @staticmethod
    def windows():
        pids = set()
        proto = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def each(hwnd, _):
            if ctypes.windll.user32.IsWindowVisible(hwnd):
                p = wintypes.DWORD()
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
                pids.add(p.value)
            return True
        ctypes.windll.user32.EnumWindows(proto(each), 0)
        return pids

    def autostarts(self):
        vals = [v for hive, _ in StartupGuard.RUNS for sub in ("Run", "RunOnce") for _, v in StartupGuard._values(hive, StartupGuard.BASE + "\\" + sub)]
        d = folders().get("Startup")
        vals += [f.name for f in d.iterdir()] if d else []
        return "\n".join(vals).lower()

    def step(self):
        net = {}
        for c in psutil.net_connections("inet"):
            if c.raddr and c.pid and c.status in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT) and public_ip(c.raddr.ip):
                net.setdefault(c.pid, set()).add((c.raddr.ip, c.raddr.port))
        shown, auto, mine = self.windows(), self.autostarts(), os.getpid()
        for p in psutil.process_iter(["pid", "name", "exe"]):
            name, exe, pid = (p.info["name"] or "").lower(), p.info["exe"] or "", p.info["pid"]
            if not exe or pid == mine or self.ctx.settings.allowed(exe):
                continue
            if name in REMOTE and self.once(("remote", exe)):
                odd = user_writable(exe)
                self.ctx.log.add(HIGH if odd else MEDIUM, self.label, f"Remote-control program running: {REMOTE[name]}",
                                 f"{exe}\nIf you did not install this, or someone on the phone asked you to, disconnect from the internet and remove it. If it is yours, trust it.", exe)
            links = net.get(pid)
            where = ", ".join(f"{i}:{n}" for i, n in sorted(links or ())[:4])
            if links and name in HOSTS | NET_SCRIPT:
                if self.once(("host", pid)):
                    self.ctx.log.add(CRITICAL if name in HOSTS else HIGH, self.label, f"{name} is on the internet (a common RAT hiding place)", f"{exe}\n{where}", exe)
                    if name in HOSTS:
                        self.ctx.restrain(p, "a Windows tool controlled from the internet", tool=True)
            elif links and user_writable(exe) and not self.signed(exe):
                self.phoning(p, exe, links, where, pid not in shown, auto)
            self.memory(p, pid, name, exe)
        self.spying()

    def phoning(self, p, exe, links, where, hidden, auto):
        try:
            st = os.stat(exe)
        except OSError:
            return
        score = rat_score(all(port not in self.WEB_PORTS for _, port in links), hidden, os.path.basename(exe).lower() in auto,
                          time.time() - st.st_ctime < 7 * 86400, bool(st.st_file_attributes & 0x6))
        if score >= 70 and self.once(("rat", exe, score >= 95)):
            level = CRITICAL if score >= 95 else HIGH
            self.ctx.log.add(level, self.label, "Unsigned hidden program is talking to the internet", f"{exe}\n{where}\nsuspicion {score}. If you made or trust it, trust it here.", exe)
            self.ctx.examine(exe, self.label, deep=True)
            hits = [n for n, s in self.ctx.engine.rules.match(p.pid) if s >= 70]
            if hits:
                level = CRITICAL
                self.ctx.log.add(CRITICAL, self.label, f"Malware signature in the memory of {os.path.basename(exe)}", f"{exe}\n{', '.join(hits[:4])}", exe)
            if hits:        # behaviour alone is never enough to freeze a program: honest home-made tools can look the same
                self.ctx.restrain(p, "behaves like a remote-access trojan and matches a malware signature")

    def memory(self, p, pid, name, exe):
        """Only Windows' own programs (where RATs hide) and unsigned user-folder ones; games and their anti-cheat are left alone."""
        if not exe.lower().startswith(WINDIR) and not (user_writable(exe) and not self.signed(exe)):
            return
        try:
            key = (pid, p.create_time())
        except psutil.Error:
            return
        if time.time() - self.looked.get(key, 0) < 600:
            return
        if len(self.looked) > 3000:
            self.looked.clear()
        self.looked[key] = time.time()
        at = injected(pid)
        if at is not None and self.once(("inject", key)):
            self.ctx.log.add(CRITICAL if exe.lower().startswith(WINDIR) else HIGH, self.label, f"A hidden program is running inside {name}", f"{exe} (process {pid}) at {at:#x}", exe)

    def spying(self):
        base = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
        for what in ("webcam", "microphone"):
            for name in StartupGuard._subkeys(winreg.HKEY_CURRENT_USER, rf"{base}\{what}\NonPackaged"):
                v = dict(StartupGuard._values(winreg.HKEY_CURRENT_USER, rf"{base}\{what}\NonPackaged\{name}"))
                exe = name.replace("#", "\\")
                using = v.get("LastUsedTimeStop") == "0" and v.get("LastUsedTimeStart", "0") != "0"
                key = ("spy", what, exe)
                if not using:
                    self.told.discard(key)
                elif os.path.isfile(exe) and not self.ctx.settings.allowed(exe) and not self.signed(exe) and self.once(key):
                    self.ctx.log.add(HIGH if user_writable(exe) else MEDIUM, self.label, f"An unsigned program is using your {what}", exe, exe)


class RootkitGuard(Guard):
    """Drivers (the way into the heart of Windows), processes hidden from Windows' own list, and weakened boot protection."""
    label, every = "Rootkit", 60.0

    def setup(self):
        self.told, self.seen, self.ghosts = set(), {}, set()

    def tell(self, level, title, detail, target):
        if (title, target) not in self.told and not self.ctx.settings.allowed(target):
            self.told.add((title, target))
            self.ctx.log.add(level, self.label, title, detail, target)

    def step(self):
        for path in loaded_drivers():
            self.driver(path, loaded=True)
        svc = r"SYSTEM\CurrentControlSet\Services"
        for name in StartupGuard._subkeys(winreg.HKEY_LOCAL_MACHINE, svc):
            v = dict(StartupGuard._values(winreg.HKEY_LOCAL_MACHINE, svc + "\\" + name))
            if v.get("Type") in ("1", "2") and v.get("ImagePath"):
                self.driver(driver_path(v["ImagePath"]), loaded=False)
            elif "svchost" in v.get("ImagePath", "").lower():
                dll = dict(StartupGuard._values(winreg.HKEY_LOCAL_MACHINE, f"{svc}\\{name}\\Parameters")).get("ServiceDll")
                if dll:
                    self.driver(os.path.expandvars(dll), loaded=False, what="service library")
        ghosts = hidden_pids()
        for pid in ghosts & self.ghosts:        # seen twice, a minute apart: not just one that was closing
            self.tell(CRITICAL, "A running process is hidden from Windows", f"process {pid}. Run a Microsoft Defender Offline scan from Windows Security.", str(pid))
        self.ghosts = ghosts
        opts = str(dict(StartupGuard._values(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control")).get("SystemStartOptions", "")).upper()
        for flag in ("TESTSIGNING", "DISABLE_INTEGRITY_CHECKS", "DEBUG"):
            if flag in opts.replace("NODEBUG", ""):
                self.tell(HIGH, f"Windows was started with driver protection weakened ({flag.lower()})", opts, flag)

    def driver(self, path, loaded, what="driver"):
        try:
            st = os.stat(path)
        except PermissionError:
            return
        except OSError:
            if loaded and not os.path.basename(path).lower().startswith("dump_"):
                self.tell(MEDIUM, "A loaded driver's file is missing from the disk", path, path)
            return
        key = (st.st_mtime_ns, st.st_size, len(self.ctx.intel.vuln_drivers), len(self.ctx.intel.hashes))
        if self.seen.get(path.lower()) == key:
            return
        try:
            sha = E.sha256_file(path)
            ok = E.signed(path) or E.cataloged(path)
        except OSError:
            return
        self.seen[path.lower()] = key
        state = "loaded now" if loaded else "installed"
        if sha in self.ctx.intel.hashes:
            self.tell(CRITICAL, "Malicious driver found", f"{path}\n{state}. Run a Microsoft Defender Offline scan from Windows Security.", path)
        elif sha in self.ctx.intel.vuln_drivers:
            self.tell(HIGH if loaded else MEDIUM, "Driver with known holes", f"{path}\n{state}. Rootkits use drivers like this one. It may belong to a hardware tool; update or remove that tool.", path)
        elif not ok:
            self.tell(CRITICAL if user_writable(path) else HIGH, f"Unsigned {what}", f"{path}\n{state}", path)


class ScanGuard(Guard):
    """Keeps the malware signatures fresh, and runs Bastion's own full scan once a day while nobody is using the PC."""
    label, every = "Scanner", 60.0

    def setup(self):
        self.began = time.time()
        self.ctx.engine.rules.load()

    def status(self):
        if self.ctx.scan_lock.locked():
            return "on"
        return "on" if self.ctx.engine.rules.count else "no signatures yet"

    def step(self):
        rules = self.ctx.engine.rules
        if self.ctx.settings["intel_updates"] and (rules.stale() or not rules.count) and time.time() - getattr(self, "tried", 0) > 3600:
            self.tried = time.time()
            rules.update()
        if time.time() - scanner.last_scan().get("at", 0) < 86400 or time.time() - self.began < 1800 or idle_seconds() < 1200:
            return
        if memory_short(2e9) or playing() or not self.ctx.scan_lock.acquire(blocking=False):
            return
        try:
            s = scanner.full(self.ctx, self.ctx.stop, polite=True)
        finally:
            self.ctx.scan_lock.release()
        if not self.ctx.stop.is_set():
            self.ctx.log.add(INFO, self.label, "Daily scan finished", scanner.summary(s))
            for r in sorted(s.found, key=lambda r: -r.verdict)[:15]:
                self.ctx.log.add(HIGH if r.verdict >= E.DANGEROUS else MEDIUM, self.label, f"{E.VERDICTS[r.verdict]} file found by the daily scan", f"{r.path}\n{'; '.join(r.reasons)}", r.path)


class AIGuard(Guard):
    """Feeds alerts to the local model, one at a time, when the PC has room for it."""
    label, every = "AI", 5.0

    def setup(self):
        self.row, self.misses = None, 0

    def status(self):
        if not self.ctx.settings["ai"]:
            return "switched off"
        return "waiting: " + self.ctx.ai.note if self.row else "on"

    def step(self):
        if not self.ctx.settings["ai"]:
            return
        if self.row is None:
            try:
                self.row = self.ctx.ai.q.get_nowait()
            except queue.Empty:
                return
        try:
            self.ctx.ai.work(self.row)
            self.row, self.misses = None, 0
        except ai.Busy as e:
            self.misses += isinstance(e, ai.NoAnswer)
            if self.misses >= 3:        # give up on this one rather than keep the rest waiting
                self.row, self.misses = None, 0
            self.ctx.ai.note = str(e)
            self.ctx.stop.wait(55)
        except Exception:
            self.row = None         # one odd alert must not block the ones behind it
            raise


class Context:
    """What the guards share, and the only place that acts on anything."""

    def __init__(self, settings, log, intel, quarantine):
        self.settings, self.log, self.intel, self.quarantine = settings, log, intel, quarantine
        self.engine = E.Engine(settings, intel)
        self.stop, self.scan_lock = threading.Event(), threading.Lock()
        self.defender = None
        self.ransom = RansomGuard(self)
        self.habits, self.ai = ai.Habits(), ai.Analyst(self)
        self.guards = []
        self.held = {}       # pid -> (psutil.Process, why)

    def start(self):
        self.guards = [self.ransom, FileGuard(self), ProcessGuard(self), StartupGuard(self), NetworkGuard(self), DriveGuard(self), DefenderGuard(self), RatGuard(self), RootkitGuard(self), AIGuard(self), ScanGuard(self)]
        self.log.listeners.append(self.ai.offer)
        for g in self.guards:
            g.start()
        telemetry.Pinger(self).start()
        self.log.add(INFO, "Bastion", "Protection started")

    def shutdown(self):
        self.stop.set()
        try:
            self.habits.save()
        except OSError:
            pass

    def examine(self, path, source, deep=False, running=None):
        r = self.engine.scan(path)
        why = "; ".join(r.reasons)
        if r.verdict == E.MALWARE:
            if running is not None:
                self.restrain(running, why)
            if self.settings["auto_respond"]:
                try:
                    self.quarantine.put(path, why)
                    self.log.add(CRITICAL, source, "Malware quarantined", f"{path}\n{why}", path)
                    return r
                except OSError as e:
                    why += f"\ncould not quarantine: {e}"
            self.log.add(CRITICAL, source, "Malware found", f"{path}\n{why}", path)
        elif r.verdict > E.CLEAN or deep and Path(path).suffix.lower() in E.RISKY:
            verdict, note = E.defender_scan(path)
            if verdict == "threat":
                self.log.add(CRITICAL, source, "Defender found a threat and is handling it", f"{path}\n{note}", path)
            elif r.verdict > E.CLEAN:
                level = HIGH if r.verdict == E.DANGEROUS else MEDIUM
                self.log.add(level, source, f"{E.VERDICTS[r.verdict]} file", f"{path}\n{why}\nDefender: {verdict}. Nothing was removed; you decide.", path)
        return r

    def restrain(self, proc, why, tool=False):
        """Freezes (never kills) an unsigned program in a user folder. Signed programs, Windows and Bastion itself are never touched,
        except that tool=True may freeze one script engine or download tool that was caught being misused."""
        if not self.settings["auto_respond"]:
            return False
        try:
            exe = proc.exe()
            mine = {os.getpid()} | {p.pid for p in psutil.Process().parents()}
            if proc.pid in mine or self.settings.allowed(exe):
                return False
            if tool:
                if os.path.basename(exe).lower() not in TOOLS:
                    return False
            elif not user_writable(exe) or E.signed(exe):
                return False
            proc.suspend()
        except (psutil.Error, OSError):
            return False
        self.held[proc.pid] = (proc, why)
        self.log.add(CRITICAL, "Bastion", f"Froze {os.path.basename(exe)}", f"{exe}\n{why}\nResume or end it on the Protection page.", exe)
        return True

    def contain(self, why):
        """Ransomware alarm: freeze whichever unsigned user-folder program is writing hardest right now."""
        if not self.settings["auto_respond"]:
            return
        first = {}
        for p in psutil.process_iter():
            try:
                first[p.pid] = (p, p.io_counters().write_bytes)
            except (psutil.Error, OSError):
                continue
        self.stop.wait(0.7)
        rates = []
        for p, w in first.values():
            try:
                rates.append((p.io_counters().write_bytes - w, p))
            except (psutil.Error, OSError):
                continue
        for rate, p in sorted(rates, key=lambda r: -r[0])[:5]:
            if rate > 300_000 and self.restrain(p, why):
                return

    def release(self, pid, end=False):
        proc, _ = self.held.pop(pid)
        try:
            proc.kill() if end else proc.resume()
        except psutil.Error:
            pass
