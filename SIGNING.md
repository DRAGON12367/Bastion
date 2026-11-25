# Getting Bastion code-signed (free, via SignPath Foundation)

A code-signed installer removes the Windows SmartScreen warning and clears nearly all of the VirusTotal heuristic detections. The [SignPath Foundation](https://signpath.org/) gives free certificates to open-source projects. This file is the checklist.

## 1. What's already done
- The project is public and MIT-licensed (OSI-approved): https://github.com/DRAGON12367/Bastion
- The full source is published.
- A CI build pipeline is provided (`.github/workflows/build.yml`) that builds the installer on GitHub Actions — SignPath signs the artifact a CI build produces, not a file from your PC.

## 2. Turn on the CI build (you, in the browser)
GitHub blocks automated tools from adding workflow files, so add these two by hand once:
1. On the repo: **Add file → Create new file**, name it `.github/workflows/build.yml`, paste the contents of this repo's local `.github/workflows/build.yml`, commit.
2. Same for `.github/workflows/virustotal.yml` (optional, scans each release).
3. Push a tag (e.g. `v1.0.1`) and confirm the **Build installer** action produces the `Bastion-installer-unsigned` artifact.

## 3. Apply to SignPath Foundation
Apply from **https://signpath.org/** (the application form is at **https://signpath.org/apply.html**; if a link 404s, start from signpath.org and follow "Apply"). You'll give them:

| Field | Value |
|---|---|
| Project name | Bastion |
| Repository | https://github.com/DRAGON12367/Bastion |
| Licence | MIT |
| CI system | GitHub Actions |
| What is signed | `Bastion-Setup-<version>.exe` (Windows installer) |
| Description | Free, open-source 24/7 security guard for Windows that works beside the user's antivirus. No telemetry by default. |

Approval is manual and can take days to a few weeks. They may ask you to confirm you are the maintainer of the GitHub account.

**Two things to know before you apply:**
- **Enable two-factor authentication** on your GitHub account (and later your SignPath account) — it's an eligibility requirement.
- **The certificate is in "SignPath Foundation"'s name, not yours.** Signed releases show SignPath Foundation as the publisher, and you add a small credit line like *"Free code signing provided by SignPath.io, certificate by SignPath Foundation."* This is normal for free OSS signing and still removes the SmartScreen warning.

## 4. After approval
SignPath gives you an organization ID and sets up a signing policy. Then:
1. Add the repository secret **`SIGNPATH_API_TOKEN`** (Settings → Secrets and variables → Actions).
2. In `.github/workflows/build.yml`, uncomment the `sign:` job and fill in your `organization-id`.
3. Tag a new release — CI builds, SignPath signs, and you attach the **signed** installer to the GitHub release.

## Note
Signing proves the file hasn't been tampered with and comes from the same project each time; it does not vouch for the code's safety. Keep the SHA-256 and VirusTotal link on each release regardless.
