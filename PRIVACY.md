# Privacy
Bastion has no account, no telemetry and no server of its own. Nothing about you or this PC is sent to anyone.

It **downloads** public lists, which shows those servers your IP address like any web visit: feodotracker.abuse.ch, spamhaus.org and GitHub (LOLDrivers, YARA Forge). Switch this off in Settings.

When something looks wrong it may ask the antivirus on this PC (Microsoft Defender) to look too. Defender has its own privacy settings.

The optional AI only talks to Ollama on this PC (127.0.0.1).

Alerts (90 days), settings, quarantine, the learned habits and AI opinions are kept in `%LOCALAPPDATA%\Bastion`. Uninstalling removes automatic start and the bait files, and leaves that folder so quarantined files are not lost. Delete it yourself when you no longer need them.
