# Bastion

A free guard for Windows PCs and Android phones, tablets, Chromebooks and TVs. It works **beside** your antivirus and does not replace it.

<p align="center">
  <a href="https://github.com/DRAGON12367/Bastion/releases/latest/download/Bastion-Setup.exe"><img alt="Download for Windows" src="docs/download-windows.svg" width="340"></a>
  &nbsp;
  <a href="https://github.com/DRAGON12367/Bastion/releases/latest/download/Bastion-Android.apk"><img alt="Download for Android" src="docs/download-android.svg" width="340"></a>
</p>
<p align="center"><b>Free</b> · MIT license · <a href="https://github.com/DRAGON12367/Bastion/releases/latest">Latest version and checksums</a></p>

## Install in 3 steps

**Windows**
1. Click **Download for Windows** above.
2. Open `Bastion-Setup.exe`. If Windows shows *"Windows protected your PC"*, click **More info**, then **Run anyway** (the installer isn't code-signed yet; see [SECURITY.md](SECURITY.md)).
3. Click **Install**. Bastion starts by itself and shows a shield in the system tray, next to the clock.

**Android phone or tablet** (Android 6.0 or newer)
1. On your phone, tap **Download for Android** above.
2. Open `Bastion-Android.apk`. When asked, allow your browser to *install unknown apps*, then tap **Install**.
3. Open Bastion. It checks your phone straight away and again every 30 minutes.

**Fire TV / Android TV / Google TV**
1. Install the free **Downloader** app from your TV's app store.
2. In Downloader, enter `https://github.com/DRAGON12367/Bastion/releases/latest/download/Bastion-Android.apk` and choose **Install**. On Fire TV, allow Downloader under *Settings > My Fire TV > Developer options > Install unknown apps*.
3. Bastion appears with your apps. Use the remote's arrows and the select button.

Already have Bastion? It tells you when a new version is out, and updates itself on Windows.

Want to check the files first? Every [release](https://github.com/DRAGON12367/Bastion/releases/latest) lists each file's SHA-256 checksum.

## Works on

| Device | Supported | Notes |
|---|---|---|
| **Windows 11** (64-bit) | ✅ Yes | Fully supported. |
| **Windows 10** (64-bit) | ✅ Yes | Fully supported. |
| Windows 11 on ARM (Surface Pro X, Snapdragon laptops) | ⚠️ Untested | Should run through Windows' built-in x64 emulation. |
| Windows 7, 8, 8.1 or 32-bit Windows | ❌ No | Too old for the Python and Qt versions Bastion uses. |
| **Android 6.0 to 15 phones** | ✅ Yes | Samsung Galaxy (S7 and newer, Note, A, M, Z Fold/Flip), Google Pixel (all) and Nexus 5X/6P, Motorola (Moto G4 and newer, Edge, Razr), OnePlus, Xiaomi / Redmi / POCO, OPPO, realme, vivo, Nothing, Nokia (HMD), Sony Xperia, LG, ASUS, Fairphone, TCL, and Android Go phones. |
| Huawei and Honor phones | ✅ Yes | EMUI, Magic UI and HarmonyOS 2 to 4. **Not** HarmonyOS NEXT / 5 (it no longer runs Android apps). |
| **Android tablets** | ✅ Yes | Samsung Galaxy Tab, Lenovo Tab, Xiaomi Pad, OnePlus Pad, Pixel Tablet and others on Android 6.0+. |
| **Amazon Fire tablets** | ✅ Yes | Fire OS 6, 7 and 8 (Fire 7, HD 8 and HD 10 from 2017 on). Not Fire OS 5 (2015-2016 models). |
| **Android TV / Google TV** | ✅ Yes | Android TV 6.0+: Chromecast with Google TV, Google TV Streamer, NVIDIA Shield, and Sony, TCL, Hisense, Philips and Sharp TVs. |
| **Amazon Fire TV** | ✅ Yes | Fire OS 6, 7 and 8: Fire TV Stick (2nd gen and newer), Stick 4K / 4K Max, Fire TV Cube, and Fire TV Edition TVs. **Not** Fire TV devices on Vega OS (they don't run Android apps). |
| Chromebooks | ⚠️ Advanced | Chromebooks with Google Play run it, but Chrome OS only installs APKs from outside Play in developer mode or with ADB from the Linux terminal. |
| Android 5.1 and older | ❌ No | Missing the security checks Bastion needs. |
| iPhone and iPad | ❌ No | Apple only allows apps from the App Store, and iOS apps can't inspect other apps. |
| Mac and Linux | ❌ No | Not available. |
| Wear OS watches | ❌ No | Not supported. |

What the Android app checks depends on the Android version. Phones on Android 9 or newer also get the Private DNS (dangerous-site blocking) check. On a TV, the screen-lock and Private DNS checks may show as "could be safer": TVs often have no such setting, so you can ignore them.

## What it does
- **Watches all the time:** new files, programs being started, start-up entries, drivers, network connections, USB drives, camera and microphone use, and ransomware behaviour.
- **Scans the whole computer** on many threads with its own engine: known-malware lists, public YARA signatures, and its own checks of programs, scripts, documents, archives, shortcuts, disc images, web pages, hidden file streams, memory, drivers, scheduled tasks and browser add-ons.
- **Hardening page:** switches on Windows and Defender protections that are off by default. Undo puts back what you had.
- **Web protection:** warns when a known phishing site is opened in your browser, checks links before you open them, and can block dangerous sites for every app with Quad9.
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

## Checking the download
**[VirusTotal scan of v1.0.0](https://www.virustotal.com/gui/file/8e27244b60c6e50984f0615e1ba06ae623418aa486f37b80517ede8acd3f234e)** — 3 of ~70 engines flag it with generic/heuristic detections, which is normal for an unsigned installer built with PyInstaller. See SECURITY.md.

## Android (beta)
Bastion for Android checks the apps on your phone for spyware and stalkerware, and checks your phone's security settings. Works on Android 6.0 and newer: phones, tablets, Fire tablets, Android TV, Google TV and Fire TV (see **Works on** above).

1. On your phone or tablet, tap **Download for Android** at the top of this page (on a TV, see the Fire TV / Android TV steps above).
2. Open it. Android asks you to allow your browser or file app to "install unknown apps": allow it, then tap **Install**.
3. Android may warn that the developer is unrecognised. That's expected for apps from outside the Play Store.

It re-checks your apps about every 30 minutes, 24/7, and notifies you when something new looks wrong. Share any link to Bastion to check it before you open it, and it helps you turn on dangerous-site blocking (Private DNS with Quad9).

What it can and can't do: it looks at which apps have powerful access (screen control, device admin, texts, microphone, location), matches apps against the public stalkerware list kept by the [Echap association](https://github.com/AssoEchap/stalkerware-indicators), and checks screen lock, encryption, security-patch age and USB debugging. Android does not let any app read other apps' data or remove apps by itself, so Bastion shows you what to look at and opens the right settings page. It sends nothing about you anywhere.

iPhone: Apple does not allow apps from outside the App Store, and iOS apps cannot inspect other apps, so there is no iPhone version.

## Code signing
Bastion participates in the free open-source code-signing program of the [SignPath Foundation](https://signpath.org/). Free code signing provided by SignPath.io, certificate by SignPath Foundation. Signing is being rolled out; releases made before it is live are unsigned and carry a published SHA-256 and VirusTotal link instead.
