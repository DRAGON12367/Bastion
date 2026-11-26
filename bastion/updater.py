"""Telling the owner about a newer Bastion, and installing it when they say so.

Asks GitHub once a day which release is newest. Nothing about the PC or the owner is sent; GitHub sees the request like any download.
An update is only ever taken from this project's own GitHub releases, only if it is newer, and only if the file's SHA-256 matches
the one GitHub itself computed for the upload. Installing always waits for the owner's click and Windows' administrator prompt."""
import ctypes
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass

import requests

from . import core

REPO = "DRAGON12367/Bastion"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
DOWNLOADS = f"https://github.com/{REPO}/releases/download/"
EVERY = 24 * 3600
MAX_SIZE = 250_000_000


def version(text):
    """(1, 2, 0) from 'v1.2.0' or '1.2.0'; None for anything else (pre-releases like 1.2.0-beta are ignored)."""
    m = re.fullmatch(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})", (text or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


@dataclass
class Update:
    version: str
    page: str
    url: str
    sha256: str
    size: int
    notes: str


def pick(release, current=core.VERSION):
    """The Windows installer in a GitHub release, if it is newer than `current` and properly described; otherwise None."""
    if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
        return None
    new, now = version(release.get("tag_name")), version(current)
    if not new or not now or new <= now:
        return None
    want = "Bastion-Setup-%d.%d.%d.exe" % new
    for a in release.get("assets") or []:
        if not isinstance(a, dict) or a.get("name") != want:
            continue
        url, digest = str(a.get("browser_download_url", "")), str(a.get("digest", ""))
        m = re.fullmatch(r"sha256:([0-9a-f]{64})", digest)
        if not url.startswith(DOWNLOADS) or not m or not 0 < int(a.get("size") or 0) <= MAX_SIZE:
            return None                 # anything unusual about the file: no offer at all
        return Update("%d.%d.%d" % new, str(release.get("html_url", "")), url, m.group(1), int(a["size"]), str(release.get("body") or "")[:2000])
    return None


def check(session=None):
    """The newest release if it is newer than this one, else None. Raises requests errors."""
    web = session or requests.Session()
    web.trust_env = False
    r = web.get(API, timeout=20, headers={"Accept": "application/vnd.github+json", "User-Agent": "Bastion-update-check"})
    r.raise_for_status()
    return pick(r.json())


def download(u, folder, progress=None, session=None):
    """Downloads an update into `folder` and returns its path, only if its SHA-256 is exactly what GitHub reported."""
    if not u.url.startswith(DOWNLOADS):
        raise ValueError("not from this project's releases")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, os.path.basename(u.url))
    tmp = path + ".part"
    h, done = hashlib.sha256(), 0
    web = session or requests.Session()
    web.trust_env = False
    with web.get(u.url, timeout=60, stream=True, headers={"User-Agent": "Bastion-update"}) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for block in r.iter_content(1 << 16):
                done += len(block)
                if done > MAX_SIZE or done > u.size:
                    raise ValueError("the download is bigger than GitHub said it would be")
                h.update(block)
                f.write(block)
                if progress:
                    progress(done, u.size)
    if h.hexdigest() != u.sha256:
        os.remove(tmp)
        raise ValueError("the download does not match the checksum GitHub published; it was deleted and not run")
    os.replace(tmp, path)
    return path


def install(path):
    """Runs the verified installer. Windows asks for administrator approval; the installer closes Bastion, updates it and starts it again."""
    if not core.FROZEN:
        raise RuntimeError("this copy runs from source; update it with git instead")
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", path, "/SILENT /SUPPRESSMSGBOXES /NORESTART", None, 1)
    if rc <= 32:
        raise RuntimeError("the update was cancelled")


class State:
    """Remembers when we last asked GitHub, so the check happens at most once a day."""

    def __init__(self, path=None):
        self.path = path or core.DATA / "update.json"
        try:
            self.d = json.loads(open(self.path, encoding="utf8").read())
        except (OSError, ValueError):
            self.d = {}

    def due(self):
        return time.time() - float(self.d.get("checked", 0)) > EVERY

    def mark(self, offered=""):
        self.d["checked"] = time.time()
        if offered:
            self.d["offered"] = offered
        try:
            with open(self.path, "w", encoding="utf8") as f:
                json.dump(self.d, f)
        except OSError:
            pass
