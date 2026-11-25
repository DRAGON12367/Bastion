# Bastion

A free guard for Windows 10 and 11 PCs (64-bit). It works **beside** your antivirus and does not replace it.

## What it does
- **Watches all the time:** new files, programs being started, start-up entries, drivers, network connections, USB drives, camera and microphone use, and ransomware behaviour.
- **Scans the whole computer** on many threads with its own engine: known-malware lists, public YARA signatures, and its own checks of programs, scripts, documents, archives, shortcuts, disc images, web pages, hidden file streams, memory, drivers, scheduled tasks and browser add-ons.
- **Hardening page:** switches on Windows and Defender protections that are off by default. Undo puts back what you had.
- **Optional AI:** if you run [Ollama](https://ollama.com), a model on your own PC explains alerts. It can raise an alert but can never trust, release or delete anything.
- **No account, no ads, no tracking:** nothing about you leaves your PC. An optional anonymous usage ping (off by default) sends only a random id and version, never your IP.

## What it does not do
No program catches everything, and this one has limits you should know:
- It has no kernel driver, so a deep enough rootkit can hide from it. Use Microsoft Defender Offline for that.
- It checks programs a fraction of a second after they start, not before.
- Programs signed by a trusted publisher are only checked by hash unless you choose the thorough scan.
- Signatures can be wrong. A match is shown to you; only exact known-malware hashes are quarantined by themselves, and you can undo that.
- Malware running as you can stop it or change its settings. It is restarted every 2 minutes, not protected the way an antivirus service is.
- Without administrator rights some Windows files cannot be read. Results say how many.

Keep Windows updated, keep a real antivirus on, and keep backups.

## Install
Run `Bastion-Setup-x.y.z.exe`. The file is not code-signed, so Windows SmartScreen will warn. Compare its SHA-256 with the one published next to it before choosing to run it.
