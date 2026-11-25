"""Bastion's own full-computer scan: many threads, no Defender. Walkers list folders while checkers examine files, everything below normal priority."""
import array
import ctypes
import hashlib
import json
import os
import queue
import re
import threading
import time
from pathlib import Path

import psutil

from . import engine as E
from .core import DATA, folders, playing, powershell

VERSION = "2"
SKIP_ATTR = 0x400 | 0x1000 | 0x40000 | 0x400000      # links, and cloud files that would be downloaded just by reading them
CACHE, LAST = DATA / "scan_clean.bin", DATA / "last_scan.json"
KEEP_DAYS = 14                                       # after this everything is looked at afresh, changed or not
ODD = {"", ".tmp", ".dat", ".bin", ".log"} | E.DECOY  # checked for hidden programs where programs can write without asking
LIBRARIES = re.compile(r"\\(site-packages|node_modules|\.?venv|__pycache__|\.git)\\", re.I)       # thousands of other people's sources
WINDIR = os.environ.get("SystemRoot", r"C:\Windows").lower()
DRIVES = 3


def fixed_drives():
    k = ctypes.windll.kernel32
    mask = k.GetLogicalDrives()
    return [f"{chr(65 + i)}:\\" for i in range(26) if mask >> i & 1 and k.GetDriveTypeW(f"{chr(65 + i)}:\\") == DRIVES]


def whole_computer():
    """Where malware lands first, then everything else."""
    f = folders()
    first = [str(f[n]) for n in ("Startup", "Downloads", "Desktop", "Temp", "Documents") if n in f]
    return first + [str(Path.home())] + fixed_drives()


def last_scan():
    try:
        return json.loads(LAST.read_text("utf8"))
    except (OSError, ValueError):
        return {}


class Scanner:
    def __init__(self, engine, cancel=None, thorough=False, remember=True, threads=None, polite=False):
        self.polite = polite            # background scans stand still while a full-screen game is on
        self.engine, self.cancel, self.thorough, self.remember = engine, cancel or threading.Event(), thorough, remember
        cpu = os.cpu_count() or 4
        self.checkers, self.walkers = threads or max(3, min(12, cpu - 4)), max(2, min(6, cpu // 2))
        self.seen = self.checked = self.unchanged = self.denied = self.errors = self.bytes = 0
        self.found, self.now, self.walking, self.waiting = [], "", True, False
        self.began = time.time()
        self.lock, self.big = threading.Lock(), threading.Semaphore(3)
        self.dirs, self.files = queue.LifoQueue(), queue.Queue(6000)
        self.pending, self.clean, self.old = 0, set(), set()
        home = str(Path.home()).lower()
        self.risky_homes = tuple(str(p).lower() + "\\" for n, p in folders().items() if n in ("Downloads", "Desktop", "Temp", "Startup"))
        self.loose = (home + "\\", os.environ.get("ProgramData", r"C:\ProgramData").lower() + "\\")

    # ---- what was clean last time
    def stamp(self):
        i = self.engine.intel
        return hashlib.sha256(f"{VERSION}|{self.engine.rules.digest}|{len(i.hashes)}|{len(i.vuln_drivers)}|{self.thorough}".encode()).digest()

    def load(self):
        if not self.remember:
            return
        try:
            raw = CACHE.read_bytes()
            if raw[:32] == self.stamp() and 0 <= time.time() - int.from_bytes(raw[32:40], "little") < KEEP_DAYS * 86400:
                a = array.array("Q")
                a.frombytes(raw[40:40 + (len(raw) - 40) // 8 * 8])
                self.old, self.since = set(a), int.from_bytes(raw[32:40], "little")
        except OSError:
            pass

    def save(self):
        keys = self.clean if not self.cancel.is_set() else self.clean | self.old
        since = getattr(self, "since", 0) if self.old else int(self.began)
        tmp = CACHE.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            f.write(self.stamp() + int(since).to_bytes(8, "little"))
            array.array("Q", keys).tofile(f)
        os.replace(tmp, CACHE)

    @staticmethod
    def key(path, st):
        return int.from_bytes(hashlib.blake2b(f"{path}|{st.st_size}|{st.st_mtime_ns}|{st.st_ctime_ns}".encode("utf8", "surrogatepass"), digest_size=8).digest(), "little")

    # ---- which files matter
    def wanted(self, path, name, size):
        if not size:
            return False
        low = name.lower()
        stem, ext = os.path.splitext(low)
        if ext in E.DEV_EXT:
            return not LIBRARIES.search(path) and path.lower().startswith(self.risky_homes)
        if ext in E.RISKY or low == "autorun.inf" or os.path.splitext(stem)[1] in E.DECOY and ext not in E.DECOY:
            return True
        return ext in ODD and size >= 512 and path.lower().startswith(self.loose)

    # ---- threads
    def run(self, roots, progress=None):
        """Returns a report. `progress(self)` is called about twice a second."""
        self.load()
        roots = [os.path.abspath(r) for r in dict.fromkeys(map(str, roots))]
        self.roots = {r.lower().rstrip("\\") for r in roots}
        self.pending = len(roots)
        for r in reversed(roots):
            self.dirs.put(r)
        walkers = [threading.Thread(target=self._guarded, args=(self._walk,), daemon=True) for _ in range(self.walkers)]
        checkers = [threading.Thread(target=self._guarded, args=(self._check,), daemon=True) for _ in range(self.checkers)]
        for t in walkers + checkers:
            t.start()
        while any(t.is_alive() for t in checkers):
            if self.walking and not any(t.is_alive() for t in walkers):
                self.walking = False
            m = psutil.virtual_memory()
            self.waiting = m.available < min(0.6e9, m.total * 0.06) or self.polite and playing()
            if progress:
                progress(self)
            time.sleep(0.4)
        self.seconds = time.time() - self.began
        self.save()
        return self

    @staticmethod
    def _guarded(fn):
        ctypes.windll.kernel32.SetThreadPriority(ctypes.c_void_p(-2), -1)
        fn()

    def _walk(self):
        while not self.cancel.is_set():
            try:
                d = self.dirs.get(timeout=0.2)
            except queue.Empty:
                with self.lock:
                    if self.pending <= 0:
                        return
                continue
            try:
                self._list(d)
            except OSError:
                with self.lock:
                    self.denied += 1
            finally:
                with self.lock:
                    self.pending -= 1

    def _list(self, d):
        sub, n, take = [], 0, []
        with os.scandir(d) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                    if st.st_file_attributes & SKIP_ATTR:
                        continue
                    if st.st_file_attributes & 0x10:
                        if not self._skip(e.path):
                            sub.append(e.path)
                        continue
                except OSError:
                    continue
                n += 1
                if self.wanted(e.path, e.name, st.st_size):
                    take.append((e.path, st))
        with self.lock:
            self.seen += n
            self.pending += len(sub)
        for s in sub:
            self.dirs.put(s)
        for item in take:
            while not self.cancel.is_set():
                try:
                    self.files.put(item, timeout=0.5)
                    break
                except queue.Full:
                    continue

    def _skip(self, path):
        low = path.lower()
        if low in self.roots or low == str(DATA).lower() or low.endswith("\\.git\\objects"):
            return True
        # Windows' component store holds second links to files that are checked in System32
        return not self.thorough and low == WINDIR + "\\winsxs"

    def _streams(self, r, path):
        """A program hidden behind an ordinary file. Looked for where downloads land."""
        if not path.lower().startswith(self.risky_homes):
            return False
        for name, size in streams(path):
            if name in ("Zone.Identifier", "SmartScreen") or size < 64:
                continue
            try:
                with open(f"{path}:{name}", "rb") as f:
                    if f.read(2) == b"MZ":
                        r.add(90, f"a program hidden behind this file (stream {name})")
                        r.verdict = E.DANGEROUS
                        return True
            except OSError:
                continue
        return False

    def _check(self):
        while not self.cancel.is_set():
            try:
                path, st = self.files.get(timeout=0.3)
            except queue.Empty:
                if not self.walking:
                    return
                continue
            while self.waiting and not self.cancel.is_set():
                time.sleep(0.5)
            k = self.key(path, st)
            if k in self.old:
                with self.lock:
                    self.unchanged += 1
                    self.clean.add(k)
                continue
            self.now = path
            try:
                if st.st_size > 8_000_000:
                    with self.big:
                        r = self.engine.scan(path, self.thorough, quiet_js=True)
                else:
                    r = self.engine.scan(path, self.thorough, quiet_js=True)
            except Exception as e:          # one odd file must not end the scan
                r = E.Result(path, error=repr(e)[:120])
            with self.lock:
                self.checked += 1
                self.bytes += st.st_size
                if r.error:
                    self.errors += 1
                elif r.verdict > E.CLEAN or self._streams(r, path):
                    self.found.append(r)
                else:
                    self.clean.add(k)


class _Stream(ctypes.Structure):
    _fields_ = [("size", ctypes.c_longlong), ("name", ctypes.c_wchar * 296)]


def streams(path):
    """Hidden second contents of a file (alternate data streams), beyond the ordinary download mark."""
    k = ctypes.windll.kernel32
    k.FindFirstStreamW.restype = ctypes.c_void_p
    d = _Stream()
    h = k.FindFirstStreamW(str(path), 0, ctypes.byref(d), 0)
    if h in (None, ctypes.c_void_p(-1).value):
        return
    try:
        while True:
            if d.name != "::$DATA":
                yield d.name.split(":")[1], d.size
            if not k.FindNextStreamW(ctypes.c_void_p(h), ctypes.byref(d)):
                return
    finally:
        k.FindClose(ctypes.c_void_p(h))


LAUNCHERS = re.compile(r"mshta|wscript|cscript|regsvr32[^\n]*(http|scrobj)|powershell[^\n]*(-e(nc\w*)?\s+[a-z0-9+/=]{40}|hidden|download|iex|http)|\\users\\public\\|\\temp\\[^\n]*\.(exe|dll|bat|ps1|vbs|js)", re.I)
BROWSERS = {"Edge": r"Microsoft\Edge", "Chrome": r"Google\Chrome", "Brave": r"BraveSoftware\Brave-Browser", "Vivaldi": "Vivaldi"}
TASKS = ("$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; "
         "Get-ScheduledTask | ?{$_.State -ne 'Disabled'} | %{$t=$_; $t.Actions | ?{$_.Execute} | %{\"T|$($t.TaskPath)$($t.TaskName)|$($_.Execute) $($_.Arguments)\"}}; "
         "Get-CimInstance -Namespace root/subscription __EventConsumer | %{\"W|$($_.Name)|$($_.CommandLineTemplate)$($_.ScriptText)\"}")


def autostart_check(ctx, add):
    """Things that start by themselves in a way honest software does not."""
    from . import guards as G
    snap = {k: v for k, v in G.StartupGuard(ctx).snapshot().items() if k.split("|")[0] in ("Run", "Hijack", "Deep")}
    for k, v in snap.items():
        kind, what = k.split("|", 1)
        if kind == "Run" and LAUNCHERS.search(v) or kind == "Hijack" and "Silent" not in what or kind == "Deep" and k.lower().endswith("\\appinit_dlls") and v.strip():
            if not ctx.settings.allowed(what):
                add("starts by itself in a way malware does", v[:200], what)
    n = 0
    for line in powershell(TASKS, 60)[1].splitlines():
        kind, _, rest = line.partition("|")
        name, _, cmd = rest.partition("|")
        n += kind in ("T", "W")
        if (kind == "T" and not name.startswith("\\Microsoft\\") and LAUNCHERS.search(cmd) or kind == "W" and cmd.strip()) and not ctx.settings.allowed(name):
            add("a scheduled task starts something the way malware does" if kind == "T" else "Windows itself was told to start something (WMI)", cmd[:200], name)
    return n


def browser_check(ctx, add):
    """Browser add-ons that came from outside the official stores."""
    n = 0
    for browser, sub in BROWSERS.items():
        for pref in (Path(os.environ["LOCALAPPDATA"]) / sub / "User Data").glob("*/Secure Preferences"):
            try:
                items = json.loads(pref.read_text("utf8")).get("extensions", {}).get("settings", {}).items()
            except (OSError, ValueError, AttributeError):
                continue
            for i, s in items:
                n += 1
                m = s.get("manifest") or {}
                url = m.get("update_url", "")
                if s.get("location") == 4 and s.get("state", 1) == 1 and not s.get("disable_reasons") or s.get("location") in (2, 3) and url and not re.match(r"https://(clients2\.google|edge\.microsoft|extensionwebstorebase\.edgesv)\.", url):
                    if not ctx.settings.allowed(i):
                        add(f"a {browser} add-on that did not come from the store", f"{m.get('name', '')} {s.get('path', '')}"[:200], i)
    return n


def system_check(ctx):
    """What is running right now: drivers, hidden processes, programs hidden inside other programs."""
    from . import guards as G
    out = []

    def add(title, detail, target, verdict=E.SUSPICIOUS):
        out.append(E.Result(target, verdict, 60, [title, detail.replace("\n", " ")]))
    k = G.RootkitGuard(ctx)
    k.setup()
    k.tell = lambda level, title, detail, target: add(title, detail, target, E.DANGEROUS if level >= G.HIGH else E.SUSPICIOUS)
    k.step()
    k.step()        # a hidden process must be seen twice
    n = 0
    for p in psutil.process_iter(["pid", "name", "exe"]):
        exe = p.info["exe"] or ""
        if p.info["pid"] == os.getpid() or not exe or not (exe.lower().startswith(WINDIR) or G.user_writable(exe)):
            continue
        n += 1
        at = G.injected(p.info["pid"])
        if at is not None and not ctx.settings.allowed(exe):
            add(f"a hidden program is running inside {p.info['name']}", f"process {p.info['pid']} at {at:#x}", exe, E.DANGEROUS)
        elif at is None and G.user_writable(exe) and not E.signed(exe) and not ctx.settings.allowed(exe):
            hits = [name for name, score in ctx.engine.rules.match(p.info["pid"]) if score >= 70]
            if hits:
                add(f"malware signature in the memory of {p.info['name']}", ", ".join(hits[:4]), exe, E.DANGEROUS)
    autostart_check(ctx, add)
    browser_check(ctx, add)
    return out, n, len(k.seen)


def full(ctx, cancel, thorough=False, remember=True, progress=None, polite=False):
    ctx.engine.rules.load()
    s = Scanner(ctx.engine, cancel, thorough, remember, polite=polite)
    s.system, s.programs, s.drivers = system_check(ctx)
    s.found += s.system
    s.run(whole_computer(), progress)
    if not cancel.is_set():
        try:
            LAST.write_text(json.dumps({"at": time.time(), "seen": s.seen, "found": len(s.found), "seconds": s.seconds, "rules": s.engine.rules.count}), "utf8")
        except OSError:
            pass
    return s


def summary(s):
    m, sec = divmod(int(s.seconds), 60)
    out = f"{'Stopped early' if s.cancel.is_set() else 'Finished'} in {m}:{sec:02d}. {s.seen:,} files seen, {s.checked:,} checked ({s.bytes / 1e9:.1f} GB), {s.unchanged:,} unchanged since last time. {len(s.found)} to look at."
    if s.errors or s.denied:
        out += f" Could not open {s.errors:,} files and {s.denied:,} folders (usually Windows' own)."
    if not s.engine.rules.count:
        out += " Malware signatures were not available, so this was rules only."
    return out
