# Security & trust

Bastion is a security tool, so you should be able to check it rather than take our word.

## Check the download
Every release lists a **SHA-256** for the installer. Before running it, confirm the file matches (PowerShell):

```
Get-FileHash Bastion-Setup-1.0.0.exe
```

## VirusTotal
Each release is scanned by [VirusTotal](https://www.virustotal.com) so you can see what ~70 antivirus engines make of the exact file we published.

**v1.0.0:** [https://www.virustotal.com/gui/file/8e27244b60c6e50984f0615e1ba06ae623418aa486f37b80517ede8acd3f234e](https://www.virustotal.com/gui/file/8e27244b60c6e50984f0615e1ba06ae623418aa486f37b80517ede8acd3f234e) — 3 of ~70 engines flag it.

All three are machine-learning / heuristic guesses, not matches to any known malware:
- **Kaspersky** `HEUR:Trojan.Python.Disin.a` — a generic label Kaspersky applies to PyInstaller-packed Python; a known false positive for Python apps.
- **DeepInstinct** `MALICIOUS` and **Trapmine** `Suspicious.low.ml.score` — enterprise ML engines scoring the file's shape.

We are reducing these through code signing and false-positive reports.

**Expect a few detections, and here is why.** Bastion is built with PyInstaller, which bundles a Python runtime. Many unsigned PyInstaller apps trigger 2–10 "generic/heuristic" flags from smaller engines. We are working on code signing (via the SignPath Foundation, free for open-source) to reduce this. If a major engine (Microsoft, Kaspersky, BitDefender, ESET) flags a release, treat that as serious and open an issue.

## Privacy
Bastion has no account and no ads. It makes no network connection unless you leave the public block-list downloads on, and it sends nothing about you anywhere. An optional **anonymous usage ping** is **off by default**; if you turn it on it sends only a random id and the version number, never your IP or anything that identifies you. See `PRIVACY.md`.

## Reporting a vulnerability
Please open a GitHub issue, or for something sensitive use GitHub's private "Report a vulnerability" button on the Security tab.
