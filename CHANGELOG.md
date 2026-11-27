# Changelog

## v1.6.0 (Windows + Android)
Stronger defenses, and the full HUD on Android.

- **Android: the full HUD.** A header with build, live clock and status chip; the reactor beside a threat radar (each blip is an app the check flagged); readouts for apps checked, flagged, settings and phishing database; live memory, network and battery graphs; and defense-module tiles for every protection and phone setting. Tablets and TVs show four tiles per row.

- **New Firewall guard.** Alerts when Windows Firewall is switched off (directly or through a policy), when a new rule opens the firewall for an unsigned program in a user folder (and scans that program), and when a rule lets the network in on a port for every program.
- **Malware check-in detection.** Unknown unsigned programs that contact the same server on a steady timer, the way remote-control malware waits for orders, are reported and scanned. Hidden ones are rated high.
- **DNS hijack alerts.** Warns when this PC's DNS servers are changed to something other than well-known services (Quad9, Cloudflare, Google, OpenDNS), a trick used to send you to fake banking and login pages.
- **19 new attack-command rules:** web installs through msiexec and the finger tool (fake-CAPTCHA attacks), forced Safe Mode and file-permission grabs (ransomware), killing security software, firewall off through PowerShell, firewall holes and port forwarding through netsh, start-up and program-hijack registry edits, reverse SSH tunnels, setup-file and helper-tool tricks, free-space wiping, and downloads into hidden folders.

## v1.5.0 (Windows + Android)
A new HUD interface on every device.

- **Windows:** a full heads-up display. Animated hex-grid backdrop with a scanning beam, glass panels with glowing corner brackets, a header with a live clock and status chip, and glyph navigation.
- **Threat radar:** every alert from the last 24 hours is a blip. Newer alerts sit nearer the centre, and the colour shows how serious it is.
- **Live telemetry:** processor, memory and network graphs for the last minute, read from this PC every second.
- **Defense modules:** all 13 guards as compact status tiles.
- **Android phones, tablets and TVs:** the same hex backdrop and bracket panels, and a live line with the time, memory in use, battery and Android version.
- Everything on screen is real data; the animations stop while the window is hidden.

## v1.4.1 (Android)
Runs on many more devices.

- **Android 6.0 and 7 phones** are now supported (was Android 8+), for example the Galaxy S7, Pixel 1 and Moto G4.
- **Android TV, Google TV and Fire TV:** Bastion appears on the TV home screen and works with a remote.
- **Tablets and Chromebooks:** the screen keeps a readable column on wide displays.
- The README lists exactly which devices work.

## v1.4.0 (Windows + Android)
A live HUD.

- **Live reactor core.** The Protection page and the phone app now open on an animated core that shows Bastion's real state: cyan when secure, amber for caution, red for an alert, and faster while scanning. It only animates while it is on screen.
- **Live feed.** A terminal-style feed types out what the guards are doing as it happens: guards coming online, alerts, scans and link checks. Everything shown is real; nothing is made up for effect.
- **HUD readouts.** Systems online, malware signatures loaded, alerts in the last 24 hours and uptime, at a glance.
- **New dark cyan theme** across every page on Windows and Android.
- Includes everything from v1.3.0 (AMSI, memory scan, strict mode, and the fix for phishing alerts and update checks).

## v1.3.0 (Windows)
Stronger scanning and blocking.

- **Your antivirus judges what Bastion un-hides.** Scripts, web pages and every hidden layer Bastion decodes (Base64, character codes, split or reversed text) are passed to the installed antivirus through Windows' Antimalware Scan Interface (AMSI). Malware that is only visible once decoded is now caught by Microsoft's own engine, not just Bastion's rules.
- **Memory scan of new unknown programs.** A few seconds after an unsigned program starts from a user folder, Bastion reads its memory with 5,000+ malware signatures, catching packed malware that only reveals itself once running. A match freezes it (you can resume it). Programs with a window, like your own games, are left alone, and nothing is scanned during a full-screen game.
- **Strict mode (optional).** One button on the Hardening page makes Defender block programs that are new and rare worldwide until its cloud vouches for them, use its strictest cloud blocking, and hold suspicious files up to 60 seconds for a cloud verdict. The strongest "block before it runs" Windows offers; it can also block your own builds, so it is off unless you turn it on, and can be turned off again.
- **Fixed:** the phishing-site alerts from 1.1.0 and the daily update check from 1.2.0 stopped after their first run (they reused a name the app uses for each guard's status). Both now keep running.
- **abuse.ch lists (optional).** Add a free abuse.ch Auth-Key in Settings to get MalwareBazaar known-malware fingerprints (collected over time) and URLhaus malware sites. Settings tell you if abuse.ch refuses the key.

## v1.2.0
Automatic update alerts on PC and phone.

- **Windows:** Bastion asks GitHub once a day whether a newer version is out, shows it on the Protection page and in a notification, and **Update now** downloads it, checks it against the SHA-256 GitHub published, and installs it (Windows asks for administrator approval). Bastion restarts by itself afterwards. Can be switched off in Settings; there's also a "Check for updates now" button.
- **Android:** checks once a day and notifies you; tap to download, and Android installs it as an update. Android only accepts it if it is signed by the same developer as the Bastion you have.
- Updates are only ever taken from this project's own GitHub releases, only if newer, never pre-releases.
- If you have 1.1.0 or older, install 1.2.0 by hand once; from then on you'll be told about updates.

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
