"""Web protection: phishing-site lists, a link checker, and reading which sites this PC has looked up (Windows' DNS cache).
Nothing here sends a link or a site name anywhere: lists are downloaded and checked on this PC."""
import array
import bisect
import ctypes
import hashlib
import ipaddress
import re
from ctypes import wintypes
from urllib.parse import urlsplit

# Brands scammers copy most, and the only domains that really belong to them.
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "msn.com", "outlook.com", "xbox.com", "bing.com",
                  "sharepoint.com", "skype.com", "windows.com", "azure.com", "office365.com", "msft.net", "microsoft365.com"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com"],
    "office365": ["office.com", "office365.com", "microsoft.com"],
    "apple": ["apple.com", "icloud.com", "apple.news"],
    "icloud": ["icloud.com", "apple.com"],
    "google": ["google.com", "google.ca", "google.co.uk", "youtube.com", "gmail.com", "googleusercontent.com", "gstatic.com", "withgoogle.com", "goo.gl", "googleapis.com"],
    "gmail": ["gmail.com", "google.com"],
    "amazon": ["amazon.com", "amazon.ca", "amazon.co.uk", "amazon.de", "amazonaws.com", "a2z.com", "amazon.in"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com", "messenger.com", "facebook.net"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "roblox": ["roblox.com", "rbxcdn.com"],
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamgames.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "discord.media"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "binance": ["binance.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "rbc": ["rbc.com", "rbcroyalbank.com"],
    "tdbank": ["td.com", "tdbank.com"],
    "scotiabank": ["scotiabank.com"],
    "interac": ["interac.ca"],
    "canadapost": ["canadapost-postescanada.ca", "canadapost.ca"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly", "s.id", "t.ly"}
SAFE, CAUTION, DANGER = 0, 1, 2


def host_of(text):
    """The site name in a link someone pasted, or None. Accepts 'example.com/x' without a scheme."""
    text = (text or "").strip().strip("<>\"'")
    m = re.search(r"(?i)\b((?:https?|hxxps?)://\S+|(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/:?#]\S*)?)", text)
    if not m:
        return None
    link = m.group(1)
    if not re.match(r"(?i)^[a-z]+://", link):
        link = "http://" + link
    try:
        host = urlsplit(link.replace("hxxp", "http", 1)).hostname
    except ValueError:
        return None
    if not host or "." not in host:
        return None
    return host.lower().rstrip(".")


def h64(host):
    return int.from_bytes(hashlib.blake2b(host.encode("utf8", "ignore"), digest_size=8).digest(), "little")


class SiteList:
    """A large set of site names kept as sorted 8-byte fingerprints: ~3 MB for 400,000 sites instead of ~40 MB of text."""

    def __init__(self, hosts=()):
        a = array.array("Q", sorted({h64(h) for h in hosts}))
        self._a = a

    def __len__(self):
        return len(self._a)

    def __contains__(self, host):
        x = h64(host)
        i = bisect.bisect_left(self._a, x)
        return i < len(self._a) and self._a[i] == x


def parse_domains(text):
    """Site names from a list that has one per line (comments and blank lines ignored)."""
    for line in text.splitlines():
        line = line.strip().lower()
        if line and not line.startswith(("#", "!", ";")) and re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+", line):
            yield line


def parse_urls(text):
    for line in text.splitlines():
        h = host_of(line)
        if h:
            yield h


def candidates(host):
    """The site itself and its 'www.'-less form. Parent domains are not used: a bad page on a shared host must not condemn the whole host."""
    yield host
    if host.startswith("www."):
        yield host[4:]


def registered(host):
    """Rough 'example.co.uk' / 'example.com' part of a host, enough to compare against a brand's own domains."""
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "gc"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def belongs(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def check_link(text, bad_site):
    """(level, headline, reasons) for a pasted link. bad_site(host) -> reason or None."""
    host = host_of(text)
    if not host:
        return CAUTION, "That doesn't look like a web link", []
    reasons, level = [], SAFE
    for h in candidates(host):
        why = bad_site(h)
        if why:
            return DANGER, "Dangerous: a known phishing or scam site", [f"{host} is on the {why}", "Don't open it, and never type a password or card number there."]
    try:
        ipaddress.ip_address(host.strip("[]"))
        reasons.append("It goes to a bare number address instead of a site name, which real companies don't do")
        level = CAUTION
    except ValueError:
        pass
    if "xn--" in host:
        reasons.append("It uses look-alike letters from another alphabet to imitate a real name")
        level = CAUTION
    words = set(re.split(r"[.\-_]", host))
    for brand, own in BRANDS.items():
        if brand in words and not belongs(host, own):        # whole words only: pineapple.com is not Apple
            reasons.append(f"It mentions {brand} but is not {brand}'s real site ({registered(host)})")
            level = CAUTION
            break
    if registered(host) in SHORTENERS or host in SHORTENERS:
        reasons.append("It is a shortened link that hides where it really goes")
        level = max(level, CAUTION)
    if host.count(".") >= 4 and re.search(r"login|signin|verify|secure|account|update|wallet", host):
        reasons.append("A very long name full of words like 'login' or 'verify' is a common phishing trick")
        level = CAUTION
    if level == SAFE:
        return SAFE, "No warning signs found", [f"{host} is not on the phishing lists Bastion uses.", "That doesn't prove it's safe: new scam sites appear every hour."]
    return level, "Be careful with this link", reasons


# ---------------------------------------------------------------- which sites this PC looked up
class _Entry(ctypes.Structure):
    pass


_Entry._fields_ = [("next", ctypes.POINTER(_Entry)), ("name", ctypes.c_void_p), ("type", wintypes.WORD), ("length", wintypes.WORD), ("flags", wintypes.DWORD)]


def dns_cache():
    """Site names in Windows' DNS cache right now, or None if Windows won't say. Read-only."""
    try:
        dns = ctypes.windll.dnsapi
        get, free = dns.DnsGetCacheDataTable, dns.DnsFree
    except (OSError, AttributeError):
        return None
    get.argtypes, get.restype = [ctypes.POINTER(ctypes.POINTER(_Entry))], wintypes.BOOL
    free.argtypes, free.restype = [ctypes.c_void_p, ctypes.c_int], None
    head = ctypes.POINTER(_Entry)()
    if not get(ctypes.byref(head)):
        return None
    names, node, n = set(), head, 0
    while node and n < 20000:
        e = node.contents
        nxt = e.next
        if e.name:
            name = ctypes.wstring_at(e.name)
            if name:
                names.add(name.lower().rstrip("."))
            free(e.name, 0)
        free(ctypes.cast(node, ctypes.c_void_p), 0)
        node, n = nxt, n + 1
    return names


# ---------------------------------------------------------------- sites visited in the browser
import glob
import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path

CHROMIUM = {"Edge": r"Microsoft\Edge", "Chrome": r"Google\Chrome", "Brave": r"BraveSoftware\Brave-Browser", "Vivaldi": "Vivaldi", "Opera": r"Opera Software\Opera Stable"}
EPOCH_1601 = 11644473600


def histories():
    """(browser, kind, path) for every browser profile's history on this account."""
    local, roaming = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
    out = []
    for name, sub in CHROMIUM.items():
        for f in glob.glob(os.path.join(local, sub, "User Data", "*", "History")) + glob.glob(os.path.join(roaming, sub, "History")):
            out.append((name, "chromium", f))
    for f in glob.glob(os.path.join(roaming, r"Mozilla\Firefox\Profiles", "*", "places.sqlite")):
        out.append(("Firefox", "firefox", f))
    return out


def _open(path, kind):
    """Reads a browser's history without disturbing the browser. Chromium writes straight into the file, so it is read in place;
    Firefox keeps recent visits in a side file, so both are copied to a private temporary folder first."""
    if kind == "chromium":
        return sqlite3.connect(Path(path).as_uri() + "?mode=ro&immutable=1", uri=True, timeout=1), None
    tmp = tempfile.mkdtemp(prefix="bastion_h_")
    for ext in ("", "-wal"):
        if os.path.exists(path + ext):
            if os.path.getsize(path + ext) > 300_000_000:
                shutil.rmtree(tmp, ignore_errors=True)
                raise OSError("history too large")
            shutil.copyfile(path + ext, os.path.join(tmp, "places.sqlite" + ext))
    return sqlite3.connect(os.path.join(tmp, "places.sqlite"), timeout=1), tmp


def new_visits(state, since=600):
    """Site names visited since the last call, per browser profile. state is a dict this function keeps up to date.
    The first look at a profile goes back `since` seconds only, so old history is never trawled."""
    found = []
    for browser, kind, path in histories():
        key = path.lower()
        try:
            mtime = os.path.getmtime(path) + (os.path.getmtime(path + "-wal") if os.path.exists(path + "-wal") else 0)
        except OSError:
            continue
        if state.get(key, {}).get("mtime") == mtime:
            continue
        last = state.get(key, {}).get("last", time.time() - since)
        db, tmp = None, None
        try:
            db, tmp = _open(path, kind)
            if kind == "chromium":
                rows = db.execute("select u.url, v.visit_time from visits v join urls u on u.id = v.url where v.visit_time > ? order by v.visit_time limit 5000",
                                  (int((last + EPOCH_1601) * 1e6),)).fetchall()
                stamp = lambda t: t / 1e6 - EPOCH_1601
            else:
                rows = db.execute("select p.url, v.visit_date from moz_historyvisits v join moz_places p on p.id = v.place_id where v.visit_date > ? order by v.visit_date limit 5000",
                                  (int(last * 1e6),)).fetchall()
                stamp = lambda t: t / 1e6
        except (sqlite3.Error, OSError):
            continue                    # being written to right now: next time
        finally:
            if db is not None:
                db.close()
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
        for url, t in rows:
            host = host_of(url) if url and url.startswith(("http://", "https://")) else None
            if host:
                found.append((browser, host))
            last = max(last, stamp(t))
        state[key] = {"mtime": mtime, "last": last}
    return found
