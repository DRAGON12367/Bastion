# Changelog

## v1.0.1
Focus of this release: **far fewer false alarms**, more detection, and getting ready for code signing.

### Safer — never removes things that aren't malware
- Bastion will **never quarantine** a file Windows lists as its own, a file signed by a trusted publisher, or Bastion itself.
- Only an **exact known-malware hash** is ever quarantined automatically; everything else is shown to you to decide, and anything moved can be restored.
- An archive is no longer removed just because one file inside it looks suspicious.
- Recognises common safe software that earlier looked suspect: Tor Browser and other Firefox forks, RuneLite and ordinary Java apps, Windows' own PowerShell scripts, the Start-menu tile cache, browser polyfills, and resource-only libraries.

### Detects more
- Reads inside PDFs, RTF and Office documents (old and new), OneNote files and disc images for the tricks malware hides there.
- Opens ZIP/JAR/TAR archives **in memory** (never to disk) to check what's inside, with protection against decompression bombs.
- Un-hides obfuscated scripts (Base64, char-code, reversed, split strings) before judging them.
- Finds programs hidden in alternate data streams, DLL side-loading, and malware signatures in a running program's memory.
- More checks for suspicious processes, scheduled tasks, WMI start-up and browser extensions installed from outside the stores.

### Fits in better
- Recognises when another antivirus is your main one, instead of warning that Defender is off.
- Pauses heavy scans and the AI while a full-screen game or video is playing, and backs off when memory is low.
- Works for any Windows user name and language; installs into Program Files; clean uninstall.
- Malware signatures are stored encrypted on disk so other antivirus tools don't mistake the rule file for a threat.

### New
- **Optional, opt-in anonymous usage counter** (off by default): if you turn it on, it sends only a random id and the version so the project can count installs — never your IP or anything personal.

## v1.0.0
First public release: 11 real-time guards, multi-threaded full-computer scan with public YARA signatures, hardening page, optional local AI, private by design.
