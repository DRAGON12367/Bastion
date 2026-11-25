"""What a file gives away by its content. Every check adds points and a plain reason; no single weak sign is enough on its own.
Everything here only reads bytes: nothing is executed, mounted or written."""
import base64
import binascii
import gzip
import io
import re
import tarfile
import zipfile
import zlib
from pathlib import Path

B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
SOFT = (OSError, EOFError, KeyError, RuntimeError, NotImplementedError, ValueError, IndexError, zlib.error, zipfile.BadZipFile, tarfile.TarError, MemoryError)


# Text found inside an unsigned program (plain or wide, any case). One of each group must appear. Plain lookups: patterns are too slow on big programs.
PROGRAM = [
    (70, "carries a ransom note", [(b"files have been encrypted", b"files are encrypted", b"files were encrypted"), (b"bitcoin", b".onion", b"tor browser", b"decryptor", b"decryption key")]),
    (40, "reads saved browser passwords", [(b"login data",), (b"local state", b"web data"), (b"encrypted_key", b"cryptunprotectdata", b"sqlite3_open")]),
    (35, "looks for cryptocurrency wallets", [(b"wallet.dat", b"exodus", b"electrum"), (b"nkbihfbeogaeaoehlefnkodbefgpgknn", b"atomic\\local storage", b"ethereum\\keystore")]),
    (35, "sends data to a chat service", [(b"api.telegram.org/bot", b"discord.com/api/webhooks", b"discordapp.com/api/webhooks")]),
    (50, "mines cryptocurrency", [(b"stratum+tcp://", b"stratum+ssl://"), (b"donate", b"hashrate", b"worker")]),
    (45, "switches off antivirus", [(b"disablerealtimemonitoring", b"disableantispyware", b"add-mppreference -exclusion")]),
    (60, "deletes recovery copies", [(b"delete shadows", b"shadowcopy delete", b"recoveryenabled no", b"delete catalog -quiet")]),
    (40, "blinds Windows' script protection", [(b"amsiscanbuffer",), (b"etweventwrite", b"virtualprotect")]),
    (25, "checks whether it is being watched", [(b"sbiedll", b"vboxguest", b"vmtoolsd", b"vboxservice"), (b"wireshark", b"x64dbg", b"ollydbg", b"procmon", b"processhacker")]),
    (50, "remote-control spyware features", [(b"copyfromscreen",), (b"getasynckeystate", b"setwindowshookex"), (b"tcpclient", b"wsaconnect")]),
    (20, "adds itself to startup", [(b"currentversion\\run",), (b"schtasks",)]),
]
# Scripts, after what hides them has been peeled off.
SCRIPT = [(p, w, re.compile(r, re.S)) for p, w, r in [
    (30, "runs text as code", r"\binvoke-expression\b|\biex\b|\bexecute(global)?\s*\(|\beval\s*\(|\bexec\s*\("),
    (25, "downloads something", r"downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|\b(iwr|irm)\b|start-bitstransfer|msxml2\.(server)?xmlhttp|winhttprequest|urlcache|urlretrieve"),
    (25, "decodes hidden content", r"frombase64string|-e(nc|ncodedcommand)\s+[a-z0-9+/=]{40,}|\bchrw?\(\s*\d+\s*\)\s*&|charcode|\[char\]\s*\d+\s*\+|b64decode|certutil\s+-decode"),
    (25, "hides its window", r"-w(indowstyle)?\s+hidden|\.run\s+[^\n]{0,200},\s*0\s*(,|$)"),
    (45, "tries to weaken antivirus", r"set-mppreference\s+[^\n]*-disable|add-mppreference\s+[^\n]*-exclusion|amsi(utils|initfailed|scanbuffer)|disableantispyware|(sc|net)\s+stop\s+(windefend|mpssvc)"),
    (60, "deletes recovery copies", r"delete\s+shadows|shadowcopy\s+delete|recoveryenabled\s+no|delete\s+catalog"),
    (20, "adds itself to startup", r"currentversion\\run|schtasks[^\n]*/create|new-scheduledtask|\\startup\\"),
    (35, "loads a program straight into memory", r"reflection\.assembly\]?::?load|\.load\(\s*\$?[a-z_]*bytes|assembly\.load\("),
    (45, "calls Windows' memory functions from a script", r"virtualalloc(ex)?|createthread|writeprocessmemory|getdelegateforfunctionpointer|getprocaddress"),
    (60, "goes for stored Windows passwords", r"reg\s+save\s+hklm\\(sam|system|security)|comsvcs(\.dll)?[^\n]{0,20}minidump|lsass\.(exe|dmp)"),
    (60, "sneaks past the administrator prompt", r"(ms-settings|mscfile)\\+shell\\+open\\+command"),
    (30, "records keys or the clipboard", r"getasynckeystate|setwindowshookex|get-clipboard[^\n]{0,80}(bc1|0x[a-f0-9]{4})"),
    (35, "sends data to a chat service", r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot"),
    (30, "reads saved browser passwords", r"login data[^\n]{0,200}|user data\\+default"),
    (45, "a hidden Python payload", r"exec\s*\(\s*[^\n]{0,80}(b64decode|marshal\.loads|zlib\.decompress|fernet)"),
    (35, "writes and starts a program", r"adodb\.stream[\s\S]{0,4000}(wscript\.shell|shell\.application)|wscript\.shell[\s\S]{0,4000}adodb\.stream"),
]]
PYTHON_TELLS = {"a hidden Python payload", "sends data to a chat service", "reads saved browser passwords"}
# A pattern is only tried when one of these words is there at all: looking for a word is many times faster than a pattern.
ANCHORS = {
    "runs text as code": ("invoke-expression", "iex", "execute", "eval", "exec"),
    "downloads something": ("download", "invoke-webrequest", "invoke-restmethod", "iwr", "irm", "start-bitstransfer", "xmlhttp", "winhttprequest", "urlcache", "urlretrieve"),
    "decodes hidden content": ("frombase64string", "-e", "chr", "charcode", "[char]", "b64decode", "certutil"),
    "hides its window": ("hidden", ".run"),
    "tries to weaken antivirus": ("mppreference", "amsi", "disableantispyware", "windefend", "mpssvc"),
    "deletes recovery copies": ("shadow", "recoveryenabled", "catalog"),
    "adds itself to startup": ("currentversion", "schtasks", "scheduledtask", "startup"),
    "loads a program straight into memory": ("assembly", "bytes"),
    "calls Windows' memory functions from a script": ("virtualalloc", "createthread", "writeprocessmemory", "getdelegate", "getprocaddress"),
    "goes for stored Windows passwords": ("hklm", "comsvcs", "lsass"),
    "sneaks past the administrator prompt": ("ms-settings", "mscfile"),
    "records keys or the clipboard": ("getasynckeystate", "setwindowshookex", "get-clipboard"),
    "sends data to a chat service": ("webhooks", "api.telegram"),
    "reads saved browser passwords": ("login data", "user data"),
    "a hidden Python payload": ("exec",),
    "writes and starts a program": ("adodb.stream",),
}
TELLING = {w for ws in ANCHORS.values() for w in ws if len(w) >= 6} | {"powershell", "mshta", "wscript"}
PACKERS = {b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".themida": "Themida", b".winlice": "WinLicense", b"MPRESS1": "MPRESS", b".aspack": "ASPack", b".enigma1": "Enigma", b".petite": "Petite", b".nsp0": "NsPack"}
WELL_KNOWN = re.compile(r"microsoft corp", re.I)
API_SETS = [
    (25, "can inject code into other programs", {b"QueueUserAPC", b"VirtualAllocEx"}),
    (30, "can copy another program's memory", {b"MiniDumpWriteDump", b"OpenProcess"}),
    (25, "downloads and starts programs", {b"URLDownloadToFileW", b"ShellExecuteW"}),
    (25, "downloads and starts programs", {b"URLDownloadToFileA", b"WinExec"}),
    (20, "encrypts and renames files", {b"CryptEncrypt", b"FindFirstFileW", b"MoveFileExW", b"CryptGenKey"}),
]


def printable(b):
    return len(b) > 8 and sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b) > 0.9


def decode(blob):
    """Readable text hidden in a piece of base64, also when it is UTF-16 or compressed first."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (ValueError, binascii.Error):
        return ""
    for wbits in (None, 47, -15):
        try:
            b = raw if wbits is None else zlib.decompressobj(wbits).decompress(raw, 400_000)
        except zlib.error:
            continue
        if b[:2] == b"MZ":
            return "MZ-PROGRAM"
        if b[1::2].count(0) > len(b) * 0.4:
            b = b.replace(b"\0", b"")
        if printable(b):
            return b.decode("latin1")
    return ""


def revealed(text, before):
    """True when undoing a trick brought up a telling word that was not readable before it."""
    low = text.lower()
    return any(w in low and w not in before for w in TELLING)


def layers(text, depth=3, limit=400_000):
    """The script as written, then what each layer of hiding turns into."""
    out, now = [text[:2_000_000]], text[:2_000_000]
    first = now.lower()
    for _ in range(depth):
        new = []
        for m in list(B64.finditer(now))[:60]:
            t = decode(m.group())
            if t:
                new.append(t)
        low = now.lower()
        for word, rx_, fn in (("[char]", re.compile(r"(?:\[char\]\s*(?:0x)?[0-9a-f]+\s*\+?\s*){6,}", re.I), lambda s: "".join(chr(int(x, 0) & 0xffff) for x in re.findall(r"0x[0-9a-f]+|\d+", s.lower()))),
                        ("chr", re.compile(r"(?:chrw?\(\s*\d+\s*\)\s*&?\s*){6,}", re.I), lambda s: "".join(chr(int(x) & 0xffff) for x in re.findall(r"\d+", s))),
                        ("", re.compile(r"(?:\b\d{2,3}\s*,\s*){20,}\d{2,3}"), lambda s: "".join(chr(int(x) & 0xff) for x in re.findall(r"\d+", s))),
                        ("\\x", re.compile(r"(?:\\x[0-9a-f]{2}){12,}", re.I), lambda s: bytes.fromhex(s.replace("\\x", "")).decode("latin1"))):
            if word not in low or not word and len(now) > 200_000:
                continue
            for m in list(rx_.finditer(now))[:20]:
                try:
                    t = fn(m.group())
                except ValueError:
                    continue
                if printable(t.encode("latin1", "replace")):
                    new.append(t)
        joined = re.sub(r"""(['"])\s*[+&]\s*\1""", "", now)                # 'down'+'load'
        joined = re.sub(r"[`^](?=[A-Za-z])", "", joined)                    # d`own^load
        if joined != now and len(now) < limit and revealed(joined, first):
            new.append(joined)
        if re.search(r"llehsrewop|gnirtsdaolnwod|noisserpxe-ekovni|ptth", now, re.I) and revealed(now[:limit][::-1], first):
            new.append(now[:limit][::-1])
        if not new:
            break
        now = "\n".join(new)[:limit]
        out.append(now)
    return out


def script(text, res, ext):
    ls = layers(text)
    hidden = "\n".join(ls[1:])
    deeper = False
    low, hidden_low = ls[0].lower(), hidden.lower()
    for pts, why, r in SCRIPT:
        if ext in (".py", ".pyw") and why not in PYTHON_TELLS and not hidden:
            continue
        if any(a in low for a in ANCHORS[why]) and r.search(low) and (ext not in (".py", ".pyw") or why in PYTHON_TELLS):
            res.add(pts, why)
        elif hidden and any(a in hidden_low for a in ANCHORS[why]) and r.search(hidden_low):
            res.add(pts, why + " (hidden)")
            deeper = True
    if "MZ-PROGRAM" in hidden:
        res.add(60, "carries a hidden program")
    elif deeper:
        res.add(20, "hides what it does under encoding")
    if max((len(x) for x in text.splitlines()), default=0) > 8000 and ext != ".js":
        res.add(20, "very long obfuscated line")


def program(pe, data, res, is_dll):
    """A program's build (the caller has already parsed it). Only used on programs nobody signed."""
    names = {i.name for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for i in d.imports if i.name}
    done = set()
    for pts, why, need in API_SETS:
        if need <= names and why not in done:
            done.add(why)
            res.add(pts, why)
    for s in pe.sections:
        n = s.Name.rstrip(b"\0")
        if n in PACKERS:
            res.add(20, f"wrapped with {PACKERS[n]} to resist inspection")
            break
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep and not is_dll:
        home = next((s for s in pe.sections if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)), None)
        if home is None or not home.Characteristics & 0x20000000:
            res.add(25, "starts from an unusual place in the file")
    if not is_dll:
        m = re.search("CompanyName".encode("utf-16-le") + rb"\0\0(?:\0\0)?((?:[\x20-\x7e]\0){4,60})", data)
        if m and WELL_KNOWN.search(m.group(1).decode("utf-16-le", "replace")):
            res.add(35, f"claims to be made by {m.group(1).decode('utf-16-le').strip()} but is not signed by them")


def text_rules(data, res):
    flat = data[:8_000_000].lower()
    wide = flat.replace(b"\0", b"")
    for pts, why, groups in PROGRAM:
        if all(any(x in flat or x in wide for x in g) for g in groups):
            res.add(pts, why)


def pdf(data, res):
    if re.search(rb"/Launch\b", data):
        res.add(60, "a PDF that starts a program")
    if re.search(rb"/(OpenAction|AA)\b", data) and re.search(rb"/(JavaScript|JS)\b", data):
        res.add(40, "a PDF that runs a script when opened")
    if re.search(rb"/EmbeddedFile", data) and re.search(rb"\.(exe|js|vbs|hta|lnk|bat|cmd|ps1|scr|iso)\)", data, re.I):
        res.add(60, "a PDF with a program inside")


def rtf(data, res):
    low = data[:8_000_000].lower()
    if b"\\objupdate" in low:
        res.add(50, "a document that loads something as soon as it opens")
    if b"\\objdata" in low:
        res.add(15, "contains an embedded object")
        hexa = re.sub(rb"[^0-9a-f]", b"", low)
        if b"4d5a9000" in hexa:
            res.add(50, "carries a hidden program")
        if b"02ce020000000000c000000000000046" in hexa or b"equation.3" in low or b"6571756174696f6e2e33" in hexa:
            res.add(60, "uses the old equation editor hole")


def ole(data, res):
    """Old-style Office files (.doc .xls .ppt)."""
    wide = lambda s: s.encode("utf-16-le")
    if wide("_VBA_PROJECT") in data or b"Attribut\0e VB_" in data:
        res.add(25, "contains macros")
        low = data.lower()
        if re.search(rb"auto_?open|document_open|workbook_open|auto_?exec", low):
            res.add(25, "macros start by themselves")
        if re.search(rb"wscript|powershell|urldownload|shell\b", low):
            res.add(20, "macros can start programs")
    if wide("Ole10Native") in data and b"MZ" in data and b"This program" in data:
        res.add(60, "carries a hidden program")


def ooxml(z, names, res):
    for n in names:
        low = n.lower()
        if low.endswith(".rels") and z.getinfo(n).file_size < 500_000:
            t = z.read(n)
            if re.search(rb"(attachedTemplate|oleObject)[^>]*Target=\"(https?:|\\\\\\\\|file:)", t, re.I) or re.search(rb"Target=\"(https?:|file:)[^>]*(attachedTemplate|oleObject)", t, re.I):
                res.add(60, "fetches its template or an object from the internet")
        elif low in ("word/document.xml",) and z.getinfo(n).file_size < 20_000_000:
            if re.search(rb"DDEAUTO|\bDDE\s+\"?c:", z.read(n), re.I):
                res.add(60, "starts a program through an old link feature")


def onenote(data, res):
    if re.search(rb"\.(hta|vbs|js|cmd|bat|wsf|lnk|exe|ps1)\b", data.replace(b"\0", b""), re.I) and re.search(rb"<script|wscript|powershell|MZ\x90", data, re.I):
        res.add(60, "a OneNote file with a program behind a button")


def disc(data, res):
    if re.search(rb"\.lnk[;\0]", data.replace(b"\0L", b"L"), re.I) or re.search(rb"\.\0l\0n\0k\0", data, re.I) or re.search(rb"\0\.\0l\0n\0k", data, re.I):
        res.add(45, "a disc image with a shortcut inside, the usual way to get past download warnings")


def members(data, ext):
    """(name, bytes) for what is inside an archive. Bounded, so a decompression bomb cannot fill memory."""
    left = 150_000_000
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for i in z.infolist()[:4000]:
                if i.is_dir() or i.flag_bits & 1 or not 0 < i.file_size <= 16_000_000 or i.file_size > 2000 * max(1, i.compress_size) or left < i.file_size:
                    continue
                yield i.filename, lambda z=z, i=i: z.open(i).read(16_000_001)
                left -= i.file_size
    elif ext in (".tar", ".tgz", ".gz") or data[:2] == b"\x1f\x8b":
        raw = data
        if data[:2] == b"\x1f\x8b":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                raw = g.read(48_000_000)
        if raw[257:262] == b"ustar":
            with tarfile.open(fileobj=io.BytesIO(raw)) as t:
                for n, m in enumerate(t):
                    if n > 4000 or left <= 0:
                        return
                    if m.isfile() and 0 < m.size <= 16_000_000:
                        yield m.name, lambda t=t, m=m: t.extractfile(m).read()
                        left -= m.size
        elif raw is not data:
            yield Path("inside").name, lambda: raw
