# Security & trust

Bastion is a security tool, so you should be able to check it rather than take our word.

## Check the download
Every release lists a **SHA-256** for the installer. Before running it, confirm the file matches (PowerShell):

```
Get-FileHash Bastion-Setup-1.0.0.exe
```

## VirusTotal
Each release is scanned by [VirusTotal](https://www.virustotal.com) and the scan links are posted in the release notes, so you can see what ~70 antivirus engines make of the exact file we published.

**Expect a few detections, and here is why.** Bastion is built with PyInstaller, which bundles a Python runtime. Many unsigned PyInstaller apps trigger 2–10 "generic/heuristic" flags from smaller engines. We are working on code signing (via the SignPath Foundation, free for open-source) to reduce this. If a major engine (Microsoft, Kaspersky, BitDefender, ESET) flags a release, treat that as serious and open an issue.

## Privacy
Bastion has no account and no ads. It makes no network connection unless you leave the public block-list downloads on, and it sends nothing about you anywhere. An optional **anonymous usage ping** is **off by default**; if you turn it on it sends only a random id and the version number, never your IP or anything that identifies you. See `PRIVACY.md`.

## Reporting a vulnerability
Please open a GitHub issue, or for something sensitive use GitHub's private "Report a vulnerability" button on the Security tab.
