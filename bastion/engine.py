"""Looking at files: known-bad hashes, file-type and content rules, signatures, Defender, quarantine, public block lists."""
import bisect
import ctypes
import hashlib
import io
import ipaddress
import json
import math
import msvcrt
import os
import re
import threading
import time
import uuid
import zipfile
import zlib
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

import pefile
import requests

try:
    import yara
except ImportError:
    yara = None

from . import amsi, detect, web
from .core import DATA, ROOT, folders, run

CLEAN, SUSPICIOUS, DANGEROUS, MALWARE = range(4)
VERDICTS = ["Clean", "Suspicious", "Dangerous", "Malware"]
PE_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".xll"}
SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".docx", ".xlsx"}
WEB_EXT = {".html", ".htm", ".xhtml", ".svg"}
# Files that start something when opened and almost never need to be downloaded.
LURE_EXT = {".jnlp": 60, ".settingcontent-ms": 60, ".application": 45, ".appinstaller": 45, ".chm": 45, ".scf": 60, ".wsh": 45}
PY_EXT = {".py", ".pyw"}
DOC_EXT = {".pdf", ".rtf", ".doc", ".xls", ".ppt", ".one"}
ARCHIVES = {".zip", ".jar", ".tar", ".gz", ".tgz"}
DISCS = {".iso", ".img", ".vhd"}
DEV_EXT = WEB_EXT | PY_EXT      # harmless by the thousand in developer folders: the scanner checks them only where downloads land
RISKY = PE_EXT | SCRIPT_EXT | MACRO_EXT | DEV_EXT | DOC_EXT | ARCHIVES | DISCS | set(LURE_EXT) | {".msi", ".lnk", ".url"}
DECOY = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".mp3", ".zip"}
MAX_READ = 32 * 1024 * 1024
WSH = re.compile(rb"(?i)wscript\.(shell|createobject|arguments|echo|quit|sleep|scriptfullname)|activexobject\(\s*[\x22\x27](wscript|scripting\.filesystemobject|adodb|shell\.application|msxml2\.(server)?xmlhttp)")
# The industry's harmless test file. Kept in two halves so this source is not itself detected.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-" + b"STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


@dataclass
class Result:
    path: str
    verdict: int = CLEAN
    score: int = 0
    reasons: list = field(default_factory=list)
    sha256: str = ""
    error: str = ""

    def add(self, points, why):
        self.score += points
        self.reasons.append(why)


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in (data.count(bytes([b])) for b in set(data)) if c)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ------------------------------------------------------------------ Authenticode
class _GUID(ctypes.Structure):
    _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]


class _FileInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("path", wintypes.LPCWSTR), ("h", wintypes.HANDLE), ("subject", ctypes.c_void_p)]


class _TrustData(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("policy", ctypes.c_void_p), ("sip", ctypes.c_void_p), ("ui", wintypes.DWORD),
                ("revoke", wintypes.DWORD), ("choice", wintypes.DWORD), ("file", ctypes.POINTER(_FileInfo)), ("action", wintypes.DWORD),
                ("state", wintypes.HANDLE), ("url", wintypes.LPCWSTR), ("flags", wintypes.DWORD), ("context", wintypes.DWORD), ("sig", ctypes.c_void_p)]


def signed(path):
    """True when the file carries a valid embedded signature from a trusted publisher."""
    try:
        guid = _GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        info = _FileInfo(ctypes.sizeof(_FileInfo), str(path), None, None)
        td = _TrustData(cb=ctypes.sizeof(_TrustData), ui=2, revoke=0, choice=1, file=ctypes.pointer(info), action=1, flags=0x1000)
        verify = ctypes.windll.wintrust.WinVerifyTrust
        verify.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.POINTER(_TrustData)]
        verify.restype = wintypes.LONG
        rc = verify(None, ctypes.byref(guid), ctypes.byref(td))
        td.action = 2
        verify(None, ctypes.byref(guid), ctypes.byref(td))
        return rc == 0
    except OSError:
        return False


def cataloged(path):
    """True when the file is listed in one of Windows' installed signature catalogs (how most drivers are signed)."""
    wt = ctypes.windll.wintrust
    wt.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminCalcHashFromFileHandle2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    wt.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
    wt.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    wt.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    with open(path, "rb") as f:
        for alg in ("SHA256", "SHA1"):
            admin = wintypes.HANDLE()
            if not wt.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, alg, None, 0):
                continue
            try:
                size, buf = wintypes.DWORD(64), ctypes.create_string_buffer(64)
                if wt.CryptCATAdminCalcHashFromFileHandle2(admin, msvcrt.get_osfhandle(f.fileno()), ctypes.byref(size), buf, 0):
                    cat = wt.CryptCATAdminEnumCatalogFromHash(admin, buf, size, 0, None)
                    if cat:
                        wt.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
                        return True
            finally:
                wt.CryptCATAdminReleaseContext(admin, 0)
    return False


def fetch(url, limit, headers=None):
    with requests.get(url, timeout=45, headers={"User-Agent": "blocklist-client/1.0", **(headers or {})}, stream=True) as r:
        r.raise_for_status()
        out, end = bytearray(), time.time() + 180
        for block in r.iter_content(1 << 16):
            out += block
            if len(out) > limit or time.time() > end:
                raise ValueError("download too large or too slow")
        return bytes(out)


def from_internet(path):
    try:
        with open(str(path) + ":Zone.Identifier", "r", errors="replace") as f:
            return "ZoneId=3" in f.read(400) or False
    except OSError:
        return False


# ------------------------------------------------------------------ rules
INJECT = [{b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"}, {b"NtUnmapViewOfSection", b"WriteProcessMemory", b"SetThreadContext"}]

# (points, meaning, every one of these must appear somewhere in the jar's classes)
JAR_RULES = [
    (10, "can start programs", [rb"java/lang/(Runtime|ProcessBuilder)", rb"exec|ProcessBuilder"]),
    (20, "unpacks hidden code while running", [rb"javax/crypto/Cipher", rb"defineClass"]),
    (30, "can record the screen", [rb"java/awt/Robot", rb"createScreenCapture"]),
    (35, "can record keys", [rb"jnativehook|NativeKeyListener"]),
    (30, "can use the webcam or microphone", [rb"sarxos/webcam|javax/sound/sampled/TargetDataLine"]),
    (40, "adds itself to startup", [rb"CurrentVersion\\+Run|Start Menu\\+Programs\\+Startup"]),
    (35, "tries to weaken antivirus or the firewall", [rb"(?i)mppreference|advfirewall|DisableTaskMgr|DisableAntiSpyware"]),
    (35, "reads saved passwords or tokens", [rb"Login Data|discord(app)?\.com/api/webhooks|launcher_accounts\.json|Local Storage[\\/]+leveldb"]),
    (10, "downloads code and loads it", [rb"java/net/URLClassLoader"]),
    (5, "uses the network", [rb"java/net/(Socket|URL|http)"]),
]
JAR_RULES = [(p, w, [re.compile(r) for r in rx]) for p, w, rx in JAR_RULES]
WEB_RULES = [
    (60, "carries a hidden program", r"TVqQAAMAAAA|TVpQAAIAAAA"),
    (30, "carries a hidden archive", r"UEsDB[A-Za-z0-9+/]{400}"),
    (30, "builds a download by itself", r"msSaveOrOpenBlob|createObjectURL[\s\S]{0,600}\.click\("),
    (15, "decodes hidden content", r"\batob\s*\(|fromCharCode"),
    (60, "starts Java or an ActiveX control", r"(?i)<applet\b|application/x-java-applet|new\s+ActiveXObject|classid\s*=\s*['\"]clsid:"),
]
WEB_RULES = [(p, w, re.compile(r)) for p, w, r in WEB_RULES]
COPIES = re.compile(r"(?i)clipboard\.writeText|execCommand\(\s*['\"]copy")
COMMAND_WORDS = re.compile(r"(?i)\b(powershell|mshta|msiexec)\b")


def _inspect_jar(data, res):
    left, text = 60_000_000, []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for i in z.infolist()[:6000]:
            if i.filename.endswith(".class") and i.file_size < 2_000_000 and left > 0:
                text.append(z.read(i))
                left -= i.file_size
    blob = b"\n".join(text)
    for pts, why, rules in JAR_RULES:
        if all(r.search(blob) for r in rules):
            res.add(pts, "Java: " + why)


def _inspect_zip(data, res):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        items = [i for i in z.infolist()[:3000] if not i.is_dir()]
    for i in items:
        n = Path(i.filename)
        ext, inner = n.suffix.lower(), Path(n.stem).suffix.lower()
        if ext in PE_EXT | SCRIPT_EXT | {".lnk", ".jar"} and inner in DECOY or any(c in n.name for c in "\u202e\u202d"):
            res.add(60, f"contains a disguised program ({n.name[-40:]})")
            return
        if len(items) <= 5 and (ext in LURE_EXT or ext in {".lnk", ".hta", ".vbe", ".jse", ".wsf", ".scr", ".pif"}):
            res.add(60, f"contains a file type used to deliver malware ({n.name[-40:]})")
            return
    if len(items) <= 5 and any(i.flag_bits & 1 and Path(i.filename).suffix.lower() in PE_EXT | SCRIPT_EXT for i in items):
        res.add(60, "a password hides the program inside from antivirus")


def inspect(path, data, res, is_signed=None, internet=False):
    name = Path(path).name
    ext = Path(path).suffix.lower()
    inner = Path(Path(path).stem).suffix.lower()
    if any(c in name for c in "\u202e\u202d\u2066\u2067"):
        res.add(70, "hidden characters disguise the file's real type")
    if ext in (PE_EXT | SCRIPT_EXT | {".lnk"}) and inner in DECOY:
        res.add(50, f"double extension ({inner}{ext})")
    pe = data[:2] == b"MZ" and len(data) > 64
    if pe and ext in DECOY and runnable(data) and r"\placeholdertilelogofolder" + "\\" not in str(path).lower():
        res.add(80, f"a program pretending to be {ext}")
    if pe:
        _inspect_pe(data, res, is_signed is False, ext)
        if is_signed:
            res.score = min(res.score, 40)
        elif is_signed is False:
            res.add(10, "not signed by a publisher")
    elif ext in SCRIPT_EXT | {".settingcontent-ms"}:
        text = data[:2_000_000]
        text = text.decode("utf-16", "replace") if text[:2] in (b"\xff\xfe", b"\xfe\xff") else text.decode("utf8", "replace")
        detect.script(text, res, ext)
    elif ext in PY_EXT:
        detect.script(data[:2_000_000].decode("utf8", "replace"), res, ext)
    elif ext == ".lnk":
        flat = (data.replace(b"\x00", b"")).lower()
        if any(s in flat for s in (b"powershell", b"mshta", b"wscript", b"cscript", b"cmd.exe /c", b"rundll32")):
            res.add(40, "shortcut starts a script engine")
            if b"http" in flat or b"hidden" in flat:
                res.add(30, "shortcut fetches or hides something")
        if re.search(rb" {60,}\S", flat):
            res.add(40, "shortcut hides its command behind blank space")
    elif data[:2] == b"PK" and (ext in MACRO_EXT or ext in DECOY):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                detect.ooxml(z, z.namelist()[:3000], res)
                macros = [n for n in z.namelist() if n.lower().endswith("vbaproject.bin")]
                if macros:
                    res.add(25, "contains macros")
                    if z.getinfo(macros[0]).file_size < 20_000_000:
                        vba = z.read(macros[0]).lower()
                        if any(s in vba for s in (b"autoopen", b"document_open", b"workbook_open")):
                            res.add(25, "macros start by themselves")
                        if any(s in vba for s in (b"shell", b"wscript", b"powershell", b"urldownload")):
                            res.add(20, "macros can start programs")
                    if ext in (".docx", ".xlsx"):
                        res.add(30, "macros in a file type that shouldn't have any")
        except detect.SOFT:
            pass
    elif data[:4] == b"%PDF" or ext == ".pdf":
        detect.pdf(data, res)
    elif data[:5] == b"{\\rtf":
        detect.rtf(data, res)
    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and ext != ".msi":
        detect.ole(data, res)
    elif ext == ".one":
        detect.onenote(data, res)
    elif ext in DISCS:
        detect.disc(data[:8_000_000], res)
    elif data[:2] == b"PK" and ext == ".jar":
        _try_zip(_inspect_jar, data, res)
    elif ext in WEB_EXT:
        text = data[:8_000_000].decode("utf8", "replace")
        for pts, why, rx in WEB_RULES:
            if rx.search(text):
                res.add(pts, why)
        if COPIES.search(text) and COMMAND_WORDS.search(text) and len(text) < 400_000:
            res.add(60, "may put a command on the clipboard for you to paste (fake CAPTCHA trick)")
        if ext == ".svg" and "<script" in text and re.search(r"atob|location|createObjectURL", text):
            res.add(60, "a picture that runs a script")
    elif ext == ".url" and re.search(rb"(?im)^(url|iconfile)\s*=\s*(file:|\\\\)", data[:4000]):
        res.add(60, "a web shortcut that opens a file from another computer")
    if ext == ".zip" and data[:2] == b"PK":
        _try_zip(_inspect_zip, data, res)
    if ext in LURE_EXT and not pe:
        res.add(LURE_EXT[ext], f"a file type often used to start malware ({ext})")
    if ext == ".inf" and name.lower() == "autorun.inf" and b"open" in data.lower():
        res.add(60, "starts a program when the drive is opened")
    if internet and res.score:
        res.add(10, "came from the internet")


def _try_zip(fn, data, res):
    try:
        fn(data, res)
    except detect.SOFT:
        pass


def runnable(data):
    """Has code that can start: resource-only libraries also begin with MZ."""
    try:
        pe = pefile.PE(data=data[:4096], fast_load=True)
        return bool(pe.OPTIONAL_HEADER.AddressOfEntryPoint) and any(s.Characteristics & 0x20000000 and s.SizeOfRawData for s in pe.sections)
    except (pefile.PEFormatError, ValueError, IndexError, AttributeError):
        return True


def _inspect_pe(data, res, unsigned=False, ext=".exe"):
    try:
        pe = pefile.PE(data=data, fast_load=True)
        if any(n in data for n in (b"WriteProcessMemory", b"GetAsyncKeyState", b"QueueUserAPC", b"MiniDumpWriteDump", b"URLDownloadToFile", b"CryptGenKey")):      # reading every import is slow and only these matter
            pe.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except (pefile.PEFormatError, ValueError, IndexError):
        res.add(15, "damaged program header")
        return
    names = {i.name for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for i in d.imports if i.name}
    if any(s <= names for s in INJECT):
        res.add(40, "can inject code into other programs")
    if {b"SetWindowsHookExA", b"GetAsyncKeyState"} & names and {b"InternetOpenA", b"InternetOpenW", b"HttpSendRequestA", b"WSAStartup"} & names:
        res.add(20, "can read keys and use the network")
    for s in pe.sections:
        if s.Characteristics & 0x20000000 and s.SizeOfRawData > 4096 and entropy(s.get_data()[:1 << 20][::13]) > 7.3:
            res.add(25, "packed or encrypted code")
            break
    if any(s.Characteristics & 0xA0000000 == 0xA0000000 and s.SizeOfRawData for s in pe.sections):
        res.add(15, "code that rewrites itself")
    if unsigned:
        try:
            detect.program(pe, data, res, bool(pe.FILE_HEADER.Characteristics & 0x2000) or ext == ".sys")
        except (AttributeError, *detect.SOFT):
            pass
        detect.text_rules(data, res)
    pe.close()


class _Blob(ctypes.Structure):
    _fields_ = [("n", wintypes.DWORD), ("p", ctypes.c_void_p)]


def dpapi(data, lock):
    """Encrypts or opens data for this Windows user."""
    buf, out = ctypes.create_string_buffer(data, len(data)), _Blob()
    src = _Blob(len(data), ctypes.addressof(buf))
    fn = ctypes.windll.crypt32.CryptProtectData if lock else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(out)):
        raise OSError("Windows data protection refused")
    try:
        return ctypes.string_at(out.p, out.n)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(out.p))


class Rules:
    """Malware signatures: YARA Forge's 'core' set, gathered from public research and picked for few false alarms. Plain text rules, compiled here."""
    URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"

    def __init__(self, folder=None):
        self.file = Path(folder or DATA / "intel") / "signatures.dat"
        self.file.parent.mkdir(parents=True, exist_ok=True)
        (self.file.parent / "yara-core.zip").unlink(missing_ok=True)      # how version 1.0 tests kept them
        self.count, self.digest, self.error, self._rules = 0, "none", "", None
        self._lock = threading.Lock()

    @staticmethod
    def build(raw):
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            name = next(n for n in z.namelist() if n.endswith(".yar"))
            if z.getinfo(name).file_size > 80_000_000:
                raise ValueError("rule file is too large")
            return yara.compile(source=z.read(name).decode("utf8", "replace"), includes=False)

    def stale(self):
        try:
            return time.time() - self.file.stat().st_mtime > 3 * 86400
        except OSError:
            return True

    def update(self):
        """Fetches a new set; the old one stays unless the new one compiles."""
        if yara is None:
            return False
        try:
            raw = fetch(self.URL, 30_000_000)
            self._use(raw, self.build(raw))
            tmp = self.file.with_suffix(".tmp")
            tmp.write_bytes(dpapi(raw, True))
            os.replace(tmp, self.file)
            self.error = ""
        except (requests.RequestException, OSError, ValueError, StopIteration, zipfile.BadZipFile, yara.Error) as e:
            self.error = str(e)[:160]
        return not self.error

    def load(self):
        with self._lock:
            if yara is None:
                self.error = "the YARA engine is not installed"
            elif self._rules is None and self.file.exists():
                try:
                    raw = dpapi(self.file.read_bytes(), False)
                    self._use(raw, self.build(raw))
                except (OSError, ValueError, StopIteration, zipfile.BadZipFile, yara.Error) as e:
                    self.error = str(e)[:160]
        return self._rules is not None

    def _use(self, raw, rules):
        self.count, self.digest, self._rules = sum(1 for _ in rules), hashlib.sha256(raw).hexdigest(), rules

    def match(self, data):
        if self._rules is None:
            return []
        try:
            found = self._rules.match(pid=data, timeout=40) if isinstance(data, int) else self._rules.match(data=data, timeout=25)
            return [(m.rule, int(m.meta.get("score", 60))) for m in found]
        except (yara.Error, ValueError, TypeError, OSError):     # too slow or odd: the other checks still count
            return []


# Signs no ordinary script shows, wherever it was written.
SEVERE = ("(hidden)", "hidden program", "under encoding", "weaken antivirus", "recovery copies", "stored Windows passwords", "administrator prompt",
          "memory functions", "double extension", "hidden characters", "pretending to be", "Python payload")


class Engine:
    def __init__(self, settings, intel, rules=None):
        self.settings, self.intel, self.rules = settings, intel, rules or Rules(intel.dir)
        self.amsi = amsi.Amsi()

    def scan(self, path, thorough=False, quiet_js=False):
        """Signed programs are trusted once their hash is checked (thorough=True looks inside them too). quiet_js leaves web-page and Node
        scripts to the signatures, because only scripts written for Windows itself can do harm when opened."""
        res = Result(str(path))
        try:
            p = Path(path)
            size, ext = p.stat().st_size, p.suffix.lower()
            with open(p, "rb") as f:
                data = f.read(4096)
                is_pe = data[:2] == b"MZ"
                odd = p.name.lower() == "autorun.inf" or any(c in p.name for c in "\u202e\u202d\u2066\u2067")
                if not (is_pe or odd or ext in RISKY or EICAR in data[:200]):
                    return res
                if is_pe or size <= MAX_READ:       # known-bad lists hold programs; hashing huge archives only costs time
                    res.sha256 = sha256_file(p)
                if self.settings.allowed(str(p), res.sha256):
                    return res
                trusted = (signed(p) or cataloged(p)) if is_pe else signed(p) if ext == ".msi" else cataloged(p) if str(p).lower().startswith(SYSTEM_PLACES[0]) else None
                if res.sha256 in self.intel.hashes:
                    res.score, res.verdict = 100, DANGEROUS if trusted else MALWARE
                    res.reasons.append("matches a known malware sample" + (", although it is signed" if trusted else ""))
                    return res
                if not trusted or thorough:
                    f.seek(0)
                    data = f.read(min(size, MAX_READ))
                    if not (quiet_js and ext == ".js" and not WSH.search(data[:2_000_000])):
                        net = from_internet(p)
                        self.judge(res, data, trusted if is_pe else None, net)
                        if ext in SCRIPT_EXT | PY_EXT and not net and res.verdict in (SUSPICIOUS, DANGEROUS) and not self.landed(p) and not any(m in w for w in res.reasons for m in SEVERE):
                            res.score, res.verdict = min(res.score, 55), CLEAN      # an ordinary tool kept on this PC, hiding nothing
                    self.signatures(res, data, trusted)
                    if not is_pe and (ext in SCRIPT_EXT | PY_EXT | WEB_EXT or ext in LURE_EXT) and not (quiet_js and ext == ".js" and not WSH.search(data[:2_000_000])):
                        self.ask_av(res, data, p.name, trusted)
                    if ext in ARCHIVES or data[:2] == b"PK" or ext in DISCS:
                        self.inside(res, data, ext, quiet_js)
            if res.sha256 in self.intel.vuln_drivers:
                res.add(60, "a driver with known holes that rootkits use to get into Windows")
                res.verdict = max(res.verdict, SUSPICIOUS)
            if ext not in RISKY and not is_pe and res.verdict < MALWARE and p.name.lower() != "autorun.inf" and res.score < 60:
                res.verdict = CLEAN
        except OSError as e:
            res.error = str(e)
        return res

    @staticmethod
    def landed(p):
        low = str(p).lower()
        return any(low.startswith(str(d).lower() + "\\") for n, d in folders().items() if n in ("Downloads", "Temp", "Startup"))

    def inside(self, res, data, ext, quiet_js, depth=2):
        """What an archive holds, unpacked in memory only. Signatures of programs inside cannot be verified there, so those get hash and signature checks."""
        try:
            for name, read in detect.members(data, ext):
                e = Path(name).suffix.lower()
                if e not in RISKY and e not in ("", ".tmp", ".dat", ".bin") or e in DEV_EXT or e == ".pdf":
                    continue
                d = read()
                r = Result(name)
                if hashlib.sha256(d).hexdigest() in self.intel.hashes or EICAR in d[:200]:
                    res.add(100, f"holds known malware ({Path(name).name[-50:]})")
                    res.verdict = DANGEROUS      # yours to decide: the rest of the archive may be wanted
                    return
                pe = d[:2] == b"MZ"
                if pe and e in DECOY:
                    r.add(80, f"a program pretending to be {e}")
                elif not pe and not (quiet_js and e == ".js" and not WSH.search(d)):
                    inspect(name, d, r)
                    if e in SCRIPT_EXT | PY_EXT | WEB_EXT:
                        self.ask_av(r, d, Path(name).name, False)
                if e in RISKY or pe:
                    self.signatures(r, d, False)
                if depth > 1 and (e in ARCHIVES or d[:2] == b"PK"):
                    self.inside(r, d, e, quiet_js, depth - 1)
                if r.score >= 60 or r.verdict > CLEAN:
                    res.add(min(95, r.score), f"inside it, {Path(name).name[-50:]}: " + "; ".join(r.reasons[:3]))
                    res.verdict = max(res.verdict, min(r.verdict, DANGEROUS), DANGEROUS if r.score >= 90 else SUSPICIOUS)     # never removed for one file inside
                    if res.score > 300:
                        return
        except detect.SOFT:
            pass

    def ask_av(self, res, data, name, trusted):
        """Lets the installed antivirus judge a script as written and every layer Bastion un-hid. Its verdict is the antivirus's own."""
        if res.verdict == MALWARE:
            return
        text = data[:2_000_000]
        text = text.decode("utf-16", "replace") if text[:2] in (b"\xff\xfe", b"\xfe\xff") else text.decode("utf8", "replace")
        for i, layer in enumerate(detect.layers(text)):
            if self.amsi.text(layer, name):
                res.add(100, "Microsoft's antivirus engine recognises this as malware" + (" once Bastion un-hid it" if i else ""))
                res.verdict = DANGEROUS if trusted else MALWARE
                return

    def signatures(self, res, data, trusted):
        """Public malware signatures. They can be wrong, so a match is reported for a decision and never acted on by itself."""
        if res.verdict == MALWARE:
            return
        for name, score in self.rules.match(data):
            if score >= 60:
                res.add(score, "matches malware signature " + name)
                res.verdict = max(res.verdict, DANGEROUS if score >= 75 and not trusted else SUSPICIOUS)

    @staticmethod
    def judge(res, data, is_signed=None, internet=False):
        if EICAR in data[:200]:
            res.score, res.verdict = 100, MALWARE
            res.reasons.append("antivirus test file (EICAR)")
            return res
        inspect(res.path, data, res, is_signed, internet)
        res.verdict = DANGEROUS if res.score >= 90 else SUSPICIOUS if res.score >= 60 else CLEAN
        return res


# ------------------------------------------------------------------ Defender
def defender_exe():
    base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows Defender\Platform"
    try:
        found = sorted(base.glob("*/MpCmdRun.exe"), key=lambda p: [int(x) for x in re.findall(r"\d+", p.parent.name)])
    except OSError:
        found = []
    fallback = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / r"Windows Defender\MpCmdRun.exe"
    return found[-1] if found else fallback if fallback.exists() else None


def defender_scan(path, timeout=300):
    """'clean', 'threat' (Defender deals with it itself) or 'unknown'. The exit code alone is not trusted: 2 also means failure."""
    exe = defender_exe()
    if exe is None:
        return "unknown", "Defender not found"
    code, out = run([str(exe), "-Scan", "-ScanType", "3", "-File", str(path)], timeout)
    low = out.lower()
    if code == 0 and "no threats" in low:
        return "clean", ""
    if re.search(r"found\s+[1-9]\d*\s+threat|threat information|threat\s+:", low):
        return "threat", out[-400:].strip()
    return ("clean", "") if code == 0 else ("unknown", out[-300:].strip())


# ------------------------------------------------------------------ quarantine
SYSTEM_PLACES = tuple(os.environ.get(v, d).lower().rstrip("\\") + "\\" for v, d in (("SystemRoot", r"C:\Windows"), ("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", r"C:\Program Files (x86)")))


def protected(path):
    """Why this must not be quarantined, or None. Asked by Quarantine itself, so nothing in Bastion can go around it."""
    p = Path(path)
    if not p.is_file():
        return "it is not a file that can be moved"
    low = os.path.realpath(p).lower()
    if low.startswith((SYSTEM_PLACES[0], str(DATA).lower() + "\\", str(ROOT).lower() + "\\")):
        return "it belongs to Windows or to Bastion"
    try:
        if cataloged(p):
            return "Windows lists it as one of its own or as a checked driver"
        if signed(p):
            return "it is signed by a trusted publisher"
    except OSError as e:
        return f"its signature could not be checked ({e})"      # when in doubt, leave it
    return None


class Quarantine:
    """Files are moved here scrambled, so they cannot run, and can be put back exactly as they were."""
    LIMIT = 300 * 1024 * 1024
    _table = bytes(b ^ 0xA5 for b in range(256))

    def __init__(self, folder=None):
        self.dir = Path(folder or DATA / "quarantine")
        self.dir.mkdir(parents=True, exist_ok=True)

    def items(self):
        out = []
        for m in self.dir.glob("*.json"):
            try:
                out.append(json.loads(m.read_text("utf8")))
            except (OSError, ValueError):
                continue
        return sorted(out, key=lambda i: -i["at"])

    def put(self, path, why):
        p = Path(path)
        no = protected(p)
        if no:
            raise OSError("left alone: " + no)
        if p.stat().st_size > self.LIMIT:
            raise OSError("file is too large to quarantine")
        data = p.read_bytes()
        item = {"id": uuid.uuid4().hex, "path": str(p), "sha256": hashlib.sha256(data).hexdigest(), "why": why, "at": time.time(), "size": len(data)}
        store = self.dir / (item["id"] + ".bq")
        with open(store, "wb") as f:
            f.write(data.translate(self._table))
            f.flush()
            os.fsync(f.fileno())
        (self.dir / (item["id"] + ".json")).write_text(json.dumps(item), "utf8")
        if hashlib.sha256(store.read_bytes().translate(self._table)).hexdigest() != item["sha256"]:
            self.delete(item["id"])
            raise OSError("quarantine copy did not verify; original left alone")
        try:
            os.chmod(p, 0o666)
            p.unlink()
        except OSError:
            self.delete(item["id"])
            raise
        return item

    def _item(self, qid):
        if not re.fullmatch(r"[0-9a-f]{32}", qid):
            raise ValueError("bad id")
        return json.loads((self.dir / (qid + ".json")).read_text("utf8"))

    def restore(self, qid):
        item = self._item(qid)
        data = (self.dir / (qid + ".bq")).read_bytes().translate(self._table)
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise OSError("stored copy is damaged")
        dest = Path(item["path"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "xb") as f:     # never overwrites
            f.write(data)
        self.delete(qid)
        return dest

    def delete(self, qid):
        self._item(qid)
        for ext in (".bq", ".json"):
            (self.dir / (qid + ext)).unlink(missing_ok=True)


# ------------------------------------------------------------------ public block lists
class Intel:
    FEEDS = {
        # Malware hashes: abuse.ch has needed a personal Auth-Key since 2026-10-21, so none are downloaded. A list of sha256 lines saved as
        # intel/hashes.txt is used if present; known malware is otherwise left to Defender.
        "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "drop": "https://www.spamhaus.org/drop/drop.txt",
        "vulndrivers": "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_vulnerable.sha256",
        "baddrivers": "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_malicious.sha256",
        # Phishing and scam sites: live phishing pages (OpenPhish), and ~400,000 active phishing site names (Phishing.Database, MIT).
        "openphish": "https://openphish.com/feed.txt",
        "phishing": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    }
    DAILY = {"phishing"}        # 11 MB: once a day is plenty
    EMPTY = hashlib.sha256(b"").hexdigest()

    def __init__(self, folder=None):
        self.dir = Path(folder or DATA / "intel")
        self.dir.mkdir(parents=True, exist_ok=True)
        self.hashes, self.vuln_drivers, self.ips, self._lo, self._hi = set(), set(), set(), [], []
        self.phish_live, self.phish, self.malsites, self.auth_key = set(), web.SiteList(), web.SiteList(), ""
        self.updated, self.errors = 0.0, {}
        self._lock = threading.Lock()
        self.load()

    def load(self):
        def text(n):
            f = self.dir / (n + ".txt")
            return f.read_text("utf8", "replace") if f.exists() else ""
        def hashes(n):
            return set(re.findall(r"(?m)^([0-9a-f]{64})\s*$", text(n).lower())) - {self.EMPTY}
        self.hashes = hashes("hashes") | hashes("baddrivers") | hashes("bazaar")
        self.bazaar = len(hashes("bazaar"))
        self.malsites = web.SiteList(m for m in re.findall(r"(?m)^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)", text("urlhaus")) if "." in m)
        self.vuln_drivers = hashes("vulndrivers")
        self.ips = set(re.findall(r"(?m)^(\d+\.\d+\.\d+\.\d+)\s*$", text("feodo")))
        self.phish_live = set(web.parse_urls(text("openphish")))
        self.phish = web.SiteList(web.parse_domains(text("phishing")))
        nets = sorted((int(n.network_address), int(n.broadcast_address)) for n in self._nets(text("drop")))
        self._lo, self._hi = [a for a, _ in nets], [b for _, b in nets]
        stamps = [(self.dir / (n + ".txt")).stat().st_mtime for n in self.FEEDS if (self.dir / (n + ".txt")).exists()]
        self.updated = min(stamps) if len(stamps) == len(self.FEEDS) else 0.0

    @staticmethod
    def _nets(text):
        for m in re.findall(r"(?m)^(\d+\.\d+\.\d+\.\d+/\d+)", text):
            try:
                yield ipaddress.IPv4Network(m)
            except ValueError:
                continue

    def update(self):
        with self._lock:
            self.errors = {}
            for name, url in self.FEEDS.items():
                f = self.dir / (name + ".txt")
                if name in self.DAILY and f.exists() and time.time() - f.stat().st_mtime < 20 * 3600:
                    continue
                try:
                    text = fetch(url, 20_000_000).decode("utf8", "replace")
                    ok = re.search(r"(?m)^(#|;|\d+\.\d+|[0-9a-fA-F]{64}\s*$|https?://\S+$|[a-z0-9-]+(\.[a-z0-9-]+)+\s*$)", text)
                    if not ok or "<html" in text[:500].lower():
                        raise ValueError("unexpected content")
                    tmp = self.dir / (name + ".tmp")
                    tmp.write_text(text, "utf8")
                    os.replace(tmp, self.dir / (name + ".txt"))
                except (requests.RequestException, ValueError, OSError) as e:
                    self.errors[name] = str(e)[:160]
            if self.auth_key:
                self._abusech()
            self.load()
        return not self.errors

    def _abusech(self):
        """MalwareBazaar (known-malware fingerprints of the last 48 hours, collected here over time) and URLhaus (malware sites),
        with the owner's free abuse.ch Auth-Key. A refusal is reported in Settings and changes nothing else."""
        key = re.sub(r"[^A-Za-z0-9]", "", self.auth_key)[:100]
        head = {"Auth-Key": key}
        try:
            text = fetch(f"https://bazaar.abuse.ch/export/txt/sha256/recent/?auth-key={key}", 30_000_000, head).decode("utf8", "replace")
            new = set(re.findall(r"(?m)^([0-9a-f]{64})\s*$", text.lower()))
            if not new:
                raise ValueError("abuse.ch refused the key or changed its download (no fingerprints came back)")
            f = self.dir / "bazaar.txt"
            old = set(re.findall(r"(?m)^([0-9a-f]{64})$", f.read_text("utf8"))) if f.exists() else set()
            tmp = self.dir / "bazaar.tmp"
            tmp.write_text("\n".join(sorted(old | new)) + "\n", "utf8")
            os.replace(tmp, f)
        except (requests.RequestException, ValueError, OSError) as e:
            self.errors["MalwareBazaar"] = str(e)[:160]
        try:
            text = fetch(f"https://urlhaus.abuse.ch/downloads/hostfile/?auth-key={key}", 30_000_000, head).decode("utf8", "replace")
            if not re.search(r"(?m)^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+\S+\.\S+", text):
                raise ValueError("abuse.ch refused the key or changed its download (no sites came back)")
            tmp = self.dir / "urlhaus.tmp"
            tmp.write_text(text, "utf8")
            os.replace(tmp, self.dir / "urlhaus.txt")
        except (requests.RequestException, ValueError, OSError) as e:
            self.errors["URLhaus"] = str(e)[:160]

    def bad_site(self, host):
        """Which phishing list a site name is on, or None."""
        host = (host or "").lower().rstrip(".")
        if host in self.phish_live:
            return "live phishing list (OpenPhish)"
        if host in self.phish:
            return "phishing site list (Phishing.Database)"
        if host in self.malsites:
            return "malware site list (URLhaus)"
        return None

    def bad_ip(self, ip):
        if ip in self.ips:
            return "botnet control server (Feodo Tracker)"
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect.bisect_right(self._lo, n) - 1
        return "criminal network block (Spamhaus DROP)" if i >= 0 and n <= self._hi[i] else None
