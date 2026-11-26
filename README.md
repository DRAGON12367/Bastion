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
Download the latest `Bastion-Setup-x.y.z.exe` from the [Releases page](https://github.com/DRAGON12367/Bastion/releases). Until signing is live (see below), SmartScreen may warn — compare the installer's SHA-256 with the one published next to it before running.

**[VirusTotal scan of v1.0.0](https://www.virustotal.com/gui/file/8e27244b60c6e50984f0615e1ba06ae623418aa486f37b80517ede8acd3f234e)** — 3 of ~70 engines flag it with generic/heuristic detections, which is normal for an unsigned installer built with PyInstaller. See SECURITY.md.

## Android (beta)
Bastion for Android checks the apps on your phone for spyware and stalkerware, and checks your phone's security settings. Works on Android 8 and newer (Pixel, Samsung and others).

1. On your phone, download `Bastion-Android-x.y.z.apk` from the [Releases page](https://github.com/DRAGON12367/Bastion/releases).
2. Open it. Android asks you to allow your browser or file app to "install unknown apps": allow it, then tap **Install**.
3. Android may warn that the developer is unrecognised. That's expected for apps from outside the Play Store.

What it can and can't do: it looks at which apps have powerful access (screen control, device admin, texts, microphone, location), matches apps against the public stalkerware list kept by the [Echap association](https://github.com/AssoEchap/stalkerware-indicators), and checks screen lock, encryption, security-patch age and USB debugging. Android does not let any app read other apps' data or remove apps by itself, so Bastion shows you what to look at and opens the right settings page. It sends nothing about you anywhere.

iPhone: Apple does not allow apps from outside the App Store, and iOS apps cannot inspect other apps, so there is no iPhone version.

## Code signing
Bastion participates in the free open-source code-signing program of the [SignPath Foundation](https://signpath.org/). Free code signing provided by SignPath.io, certificate by SignPath Foundation. Signing is being rolled out; releases made before it is live are unsigned and carry a published SHA-256 and VirusTotal link instead.
