# Privacy
Bastion has no account and no ads. By default it has no telemetry and keeps nothing about you.

**Optional, opt-in usage ping (off by default).** If you turn it on in Settings, Bastion sends a random id made on your PC and the version number to the project's counter, so we can see how many people use it. It is never sent unless you choose Yes. It carries no IP address, no name, no file names and nothing about your PC, and the counter does not store IP addresses. Turn it off any time and nothing more is sent.

It **downloads** public lists, which shows those servers your IP address like any web visit: feodotracker.abuse.ch, spamhaus.org and GitHub (LOLDrivers, YARA Forge). Switch this off in Settings.

When something looks wrong it may ask the antivirus on this PC (Microsoft Defender) to look too. Defender has its own privacy settings.

The optional AI only talks to Ollama on this PC (127.0.0.1).

Alerts (90 days), settings, quarantine, the learned habits and AI opinions are kept in `%LOCALAPPDATA%\Bastion`. Uninstalling removes automatic start and the bait files, and leaves that folder so quarantined files are not lost. Delete it yourself when you no longer need them.

**Android app.** It looks at the list of installed apps and their permissions on your phone, and downloads the public stalkerware list from GitHub. Nothing about you, your apps or your phone is sent anywhere, and its data is excluded from cloud backups.
