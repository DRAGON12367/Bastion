# Privacy
Bastion has no account and no ads. By default it has no telemetry and keeps nothing about you.

**Optional, opt-in usage ping (off by default).** If you turn it on in Settings, Bastion sends a random id made on your PC and the version number to the project's counter, so we can see how many people use it. It is never sent unless you choose Yes. It carries no IP address, no name, no file names and nothing about your PC, and the counter does not store IP addresses. Turn it off any time and nothing more is sent.

**Browser check (Windows, can be switched off).** Bastion reads the names of sites newly opened in your browsers (from each browser's own history file on your PC) and checks them against phishing lists on your PC. It does not read page contents, does not keep a record of your browsing, and sends nothing anywhere. Only the time of the last visit it checked is remembered.

**Update check.** Once a day Bastion (Windows and Android) asks GitHub which release is newest. Nothing about you or your device is sent; GitHub sees the request like any download. On Windows you can switch it off in Settings.

It **downloads** public lists, which shows those servers your IP address like any web visit: feodotracker.abuse.ch, spamhaus.org, openphish.com and GitHub (LOLDrivers, YARA Forge, Phishing.Database). The optional Quad9 setting sends your DNS lookups to Quad9 (Swiss non-profit, no IP logging) instead of your internet provider. Switch this off in Settings.

Bastion also hands scripts and web pages it is checking, and what it decodes from them, to the antivirus on this PC through Windows' Antimalware Scan Interface (AMSI). That stays on your PC; what the antivirus does with it is covered by its own privacy settings. If you add an abuse.ch Auth-Key, it is sent to abuse.ch only to download their lists.

When something looks wrong it may ask the antivirus on this PC (Microsoft Defender) to look too. Defender has its own privacy settings.

The optional AI only talks to Ollama on this PC (127.0.0.1).

Alerts (90 days), settings, quarantine, the learned habits and AI opinions are kept in `%LOCALAPPDATA%\Bastion`. Uninstalling removes automatic start and the bait files, and leaves that folder so quarantined files are not lost. Delete it yourself when you no longer need them.

**Android app.** It looks at the list of installed apps and their permissions on your phone, and downloads the public stalkerware and phishing lists from GitHub and OpenPhish. Links you check are checked on the phone and never sent anywhere. It checks whether Private DNS is on, and shows notifications about new risky apps. Nothing about you, your apps or your phone is sent anywhere, and its data is excluded from cloud backups.
