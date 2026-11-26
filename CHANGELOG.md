# Changelog

## v1.1.0
Web protection on PC and phone, and 24/7 checks on Android.

### Windows
- **Phishing-site alerts:** checks each site newly opened in Edge, Chrome, Brave, Vivaldi, Opera or Firefox against ~400,000 known phishing sites (Phishing.Database) and live phishing pages (OpenPhish), and warns you if you open one. Only site names are looked at, on your PC; nothing is sent. Can be switched off in Settings.
- **Block dangerous websites (Quad9):** one button on the Hardening page points your wired and Wi-Fi connections at Quad9, which refuses known malware and phishing sites for every browser and app. VPNs keep their own settings; your old DNS is saved and can be restored.
- **Check a link:** paste any link on the Scan page to see if it's a known phishing site or uses common tricks (fake brand names, look-alike letters, shortened or bare-number links).

### Android 1.1.0
- **24/7 checks:** re-checks your apps about every 30 minutes and after a restart, and notifies you when a new app looks like spyware or an app has just been given control of your screen or device-admin rights.
- **Check a link:** paste a link, or share it to Bastion from your browser or messages.
- **Dangerous-site blocking check:** tells you whether Private DNS blocks malware sites, and helps you turn on Quad9 in two taps.
- Phishing lists are kept on the phone (about 3 MB); the large list only downloads on Wi-Fi.

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
