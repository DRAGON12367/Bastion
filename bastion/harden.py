"""Switching on Defender's advanced layers. Needs administrator approval (Windows asks). What was set before is saved first, so it can be undone."""
import base64
import ctypes
import hashlib
import json
import os
import re
import time
import winreg

from .core import DATA, quoted

BACKUP = DATA / "defender_before.json"
RESULT = DATA / "harden_result.txt"
REG_BACKUP = DATA / "windows_before.json"
DNS_BACKUP = DATA / "dns_before.json"
STRICT_BACKUP = DATA / "strict_before.json"
PREVALENCE = "01443614-cd74-433a-9ec2-2ecdbfb8e8f7"
QUAD9 = ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]

# Microsoft's attack-surface-reduction rules. Left out on purpose: "block programs that are rare or new", which would stop your own games and tools.
BLOCK = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "Abuse of vulnerable signed drivers",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Office starting other programs",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Office creating programs",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Office injecting into other programs",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Office mail starting other programs",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Adobe Reader starting other programs",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Programs arriving by e-mail",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "Scripts launching downloaded programs",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Obfuscated scripts",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Macros calling Windows directly",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Password theft from Windows",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Hidden startup through WMI",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "Ransomware (advanced)",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "Forcing a restart into Safe Mode",
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "Copied or faked Windows tools",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Untrusted programs on USB drives",
}
AUDIT = {"d1e49aac-8f56-4280-b9ba-993a6d77406c": "Remote-style program launches (log only)"}

_EDGE, _SYS = r"SOFTWARE\Policies\Microsoft\Edge", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
# (layer, key under HKEY_LOCAL_MACHINE, value name, wanted)
REG = [
    ("Browser drive-by block", _EDGE, "PreventSmartScreenPromptOverride", 1),       # no "continue anyway" on malicious sites
    ("Browser drive-by block", _EDGE, "DownloadRestrictions", 4),                   # malicious downloads are refused
    ("Browser drive-by block", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1),
    ("Browser drive-by block", r"SOFTWARE\Policies\Microsoft\Windows\System", "ShellSmartScreenLevel", "Warn"),
    ("Java and ActiveX in web pages", _EDGE, "InternetExplorerIntegrationLevel", 0),  # Internet Explorer mode is the only place they still run
    ("Java and ActiveX in web pages", _EDGE, "InternetExplorerIntegrationReloadInIEModeAllowed", 0),
    ("USB auto-run", _SYS + r"\Explorer", "NoDriveTypeAutoRun", 255),
    ("USB auto-run", _SYS + r"\Explorer", "NoAutorun", 1),
    ("Silent administrator rights", _SYS + r"\System", "EnableLUA", 1),
    ("Silent administrator rights", _SYS + r"\System", "ConsentPromptBehaviorAdmin", 2),
    ("Silent administrator rights", _SYS + r"\System", "PromptOnSecureDesktop", 1),
    ("Remote control by Windows", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1),
    ("Remote control by Windows", r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 0),
    ("Remote control by Windows", r"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start", 4),
    ("Vulnerable driver block", r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", 1),
]
REG_NOTES = {
    "Browser drive-by block": "Edge refuses malicious sites and downloads, with no way to click past",
    "Java and ActiveX in web pages": "Closes Internet Explorer mode, the last place they run",
    "USB auto-run": "Nothing starts by itself from a drive",
    "Silent administrator rights": "Windows always asks, so malware cannot raise itself quietly",
    "Remote control by Windows": "Remote Desktop, Remote Assistance and Remote Registry stay off",
    "Vulnerable driver block": "Windows refuses drivers rootkits are known to abuse",
}
# Windows tools that malware uses to fetch its next stage. They work as before, but not over the internet.
NO_NET = ["mshta", "wscript", "cscript", "regsvr32", "certutil", "bitsadmin", "hh", "cmstp"]
FW = "Bastion web block"


def reg_read(key, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def firewall_on():
    key = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    n = 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                n += f"|Name={FW} " in str(winreg.EnumValue(k, i)[1])
    except OSError:
        pass
    return n >= len(NO_NET)


def _q(v):
    return str(int(v)) if isinstance(v, int) else "'" + str(v).replace("'", "''") + "'"


def _set(key, name, v):
    path, kind = "HKLM:\\" + key, "DWord" if isinstance(v, int) else "String"
    return f"if (-not (Test-Path '{path}')) {{ New-Item -Path '{path}' -Force | Out-Null }}; New-ItemProperty -Path '{path}' -Name '{name}' -Value {_q(v)} -PropertyType {kind} -Force | Out-Null"


def _steps(steps):
    """Each step stands alone, so one refusal does not leave the rest undone; everything that failed is reported."""
    out = ["$ErrorActionPreference='Stop'; $bad=@()"]
    out += [f"try {{ {s} }} catch {{ $bad += $_.Exception.Message }}" for s in steps]
    out.append(f"if ($bad.Count) {{ 'Some layers were refused: ' + ($bad -join ' | ') | Set-Content -Encoding utf8 {quoted(RESULT)} }} else {{ 'OK' | Set-Content -Encoding utf8 {quoted(RESULT)} }}")
    return "\n".join(out)


CAPTURE = ("$p=Get-MpPreference; @{np=[int]$p.EnableNetworkProtection;cfa=[int]$p.EnableControlledFolderAccess;cloud=[int]$p.CloudBlockLevel;"
           "pua=[int]$p.PUAProtection;ids=@($p.AttackSurfaceReductionRules_Ids|?{$_});acts=@($p.AttackSurfaceReductionRules_Actions|?{$_ -ne $null})}|ConvertTo-Json -Compress")


def apply_script():
    ids = list(BLOCK) + list(AUDIT)
    acts = ["Enabled"] * len(BLOCK) + ["AuditMode"] * len(AUDIT)
    before = json.dumps([reg_read(k, n) for _, k, n, _ in REG]).replace("'", "''")
    tools = ",".join(f"'{n}'" for n in NO_NET)
    return _steps([
        f"if (-not (Test-Path {quoted(BACKUP)})) {{ {CAPTURE} | Set-Content -Encoding utf8 {quoted(BACKUP)} }}",
        f"if (-not (Test-Path {quoted(REG_BACKUP)})) {{ '{before}' | Set-Content -Encoding utf8 {quoted(REG_BACKUP)} }}",
        "Set-MpPreference -EnableNetworkProtection Enabled -CloudBlockLevel High -PUAProtection Enabled",
        "Set-MpPreference -EnableControlledFolderAccess AuditMode",
        f"Add-MpPreference -AttackSurfaceReductionRules_Ids {','.join(ids)} -AttackSurfaceReductionRules_Actions {','.join(acts)}",
        *[_set(k, n, v) for _, k, n, v in REG],
        f"Remove-NetFirewallRule -DisplayName '{FW} *' -ErrorAction SilentlyContinue",
        f'foreach ($n in {tools}) {{ foreach ($d in "System32","SysWOW64") {{ $e="$env:SystemRoot\\$d\\$n.exe"; if (Test-Path $e) {{ '
        f'New-NetFirewallRule -DisplayName "{FW} $n $d" -Direction Outbound -Program $e -Action Block -Profile Any | Out-Null }} }} }}',
        "Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block",
    ])


def undo_script():
    b = json.loads(BACKUP.read_text("utf-8-sig"))
    ids = list(BLOCK) + list(AUDIT)
    steps = [f"Set-MpPreference -EnableNetworkProtection {int(b['np'])} -CloudBlockLevel {int(b['cloud'])} -PUAProtection {int(b['pua'])} -EnableControlledFolderAccess {int(b['cfa'])}",
             f"Remove-MpPreference -AttackSurfaceReductionRules_Ids {','.join(ids)}"]
    before = [(i, a) for i, a in zip(b.get("ids") or [], b.get("acts") or []) if re.fullmatch(r"[0-9A-Fa-f-]{36}", str(i))]
    if before:
        steps.append(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {','.join(str(i) for i, _ in before)} -AttackSurfaceReductionRules_Actions {','.join(str(int(a)) for _, a in before)}")
    if REG_BACKUP.exists():
        for (_, k, n, _), v in zip(REG, json.loads(REG_BACKUP.read_text("utf-8-sig"))):
            steps.append(_set(k, n, v) if v is not None else f"Remove-ItemProperty -Path 'HKLM:\\{k}' -Name '{n}' -ErrorAction SilentlyContinue")
        steps += [f"Remove-NetFirewallRule -DisplayName '{FW} *' -ErrorAction SilentlyContinue",
                  "Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured", f"Remove-Item {quoted(REG_BACKUP)}"]
    return _steps(steps + [f"Remove-Item {quoted(BACKUP)}"])


def strict_on_script():
    """Strict mode: Defender blocks programs that are new and rare worldwide until its cloud vouches for them, uses its strictest cloud
    blocking, and holds a suspicious file up to 60 seconds for a cloud verdict. Strongest blocking Windows offers; may block your own builds."""
    return _steps([
        f"if (-not (Test-Path {quoted(STRICT_BACKUP)})) {{ $p=Get-MpPreference; $i=[array]::IndexOf(@($p.AttackSurfaceReductionRules_Ids|%{{\"$_\".ToLower()}}), '{PREVALENCE}'); "
        f"@{{cloud=[int]$p.CloudBlockLevel; timeout=[int]$p.CloudExtendedTimeout; had=[int]($i -ge 0); act=$(if ($i -ge 0) {{ [int]@($p.AttackSurfaceReductionRules_Actions)[$i] }} else {{ 0 }})}} | ConvertTo-Json | Set-Content -Encoding utf8 {quoted(STRICT_BACKUP)} }}",
        f"Add-MpPreference -AttackSurfaceReductionRules_Ids {PREVALENCE} -AttackSurfaceReductionRules_Actions Enabled",
        "Set-MpPreference -CloudBlockLevel HighPlus -CloudExtendedTimeout 50",
    ])


def strict_off_script():
    return _steps([
        f"if (Test-Path {quoted(STRICT_BACKUP)}) {{ $b = Get-Content -Raw {quoted(STRICT_BACKUP)} | ConvertFrom-Json; "
        "Set-MpPreference -CloudBlockLevel ([int]$b.cloud) -CloudExtendedTimeout ([int]$b.timeout); "
        f"if ([int]$b.had -eq 1) {{ Add-MpPreference -AttackSurfaceReductionRules_Ids {PREVALENCE} -AttackSurfaceReductionRules_Actions ([int]$b.act) }} else {{ Remove-MpPreference -AttackSurfaceReductionRules_Ids {PREVALENCE} }}; "
        f"Remove-Item {quoted(STRICT_BACKUP)} }} else {{ Remove-MpPreference -AttackSurfaceReductionRules_Ids {PREVALENCE} }}",
    ])


def quad9_on():
    """True when a network connection on this PC uses Quad9."""
    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                if "9.9.9.9" in str(reg_read(base + "\\" + winreg.EnumKey(k, i), "NameServer") or ""):
                    return True
    except OSError:
        pass
    return False


def dns_block_script():
    """Points the PC's wired and Wi-Fi connections at Quad9, which refuses to look up known malware and phishing sites, for every browser
    and app. What was there before is saved first. VPN adapters are left alone, so a VPN keeps its own DNS."""
    nics = "Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }"
    return _steps([
        f"if (-not (Test-Path {quoted(DNS_BACKUP)})) {{ $b=@{{}}; foreach ($n in {nics}) {{ $b[[string]$n.ifIndex]=@((Get-DnsClientServerAddress -InterfaceIndex $n.ifIndex).ServerAddresses) }}; $b | ConvertTo-Json | Set-Content -Encoding utf8 {quoted(DNS_BACKUP)} }}",
        f"foreach ($n in {nics}) {{ Set-DnsClientServerAddress -InterfaceIndex $n.ifIndex -ServerAddresses {','.join(repr(a) for a in QUAD9)} }}",
        "foreach ($a in '9.9.9.9','149.112.112.112') { if (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue) { "
        "try { Add-DnsClientDohServerAddress -ServerAddress $a -DohTemplate 'https://dns.quad9.net/dns-query' -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop } "
        "catch { Set-DnsClientDohServerAddress -ServerAddress $a -DohTemplate 'https://dns.quad9.net/dns-query' -AllowFallbackToUdp $true -AutoUpgrade $true } } }",
        "Clear-DnsClientCache",
    ])


def dns_restore_script():
    """Puts back the DNS each connection had. Only addresses that really are IP addresses are restored, whatever the saved file says."""
    return _steps([
        f"if (Test-Path {quoted(DNS_BACKUP)}) {{ $b = Get-Content -Raw {quoted(DNS_BACKUP)} | ConvertFrom-Json; "
        "foreach ($p in $b.PSObject.Properties) { $i=[int]$p.Name; $ips=@($p.Value | Where-Object { $x=$null; [Net.IPAddress]::TryParse([string]$_, [ref]$x) }); "
        "if ($ips.Count) { Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses $ips } else { Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses } } "
        f"Remove-Item {quoted(DNS_BACKUP)} }} else {{ Get-NetAdapter -Physical | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }} }}",
        "Clear-DnsClientCache",
    ])


def run_elevated(script, timeout=180):
    """Windows shows its administrator prompt. The script goes by file, and the raised part refuses it if a single byte was swapped. Returns (ok, message)."""
    RESULT.unlink(missing_ok=True)
    body = script.encode("utf8")
    file = DATA / "harden.ps1"
    file.write_bytes(body)
    boot = (f"$b=[IO.File]::ReadAllBytes({quoted(file)}); $h=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)).Replace('-','');"
            f"if ($h -eq '{hashlib.sha256(body).hexdigest()}') {{ & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) }}")
    enc = base64.b64encode(boot.encode("utf-16-le")).decode()
    shell = os.path.join(os.environ["SystemRoot"], r"System32\WindowsPowerShell\v1.0\powershell.exe")
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", shell, "-NoProfile -EncodedCommand " + enc, None, 0)
    if rc <= 32:
        return False, "Cancelled, nothing was changed."
    end = time.time() + timeout
    while time.time() < end:
        if RESULT.exists():
            time.sleep(0.3)
            msg = RESULT.read_text("utf-8-sig").strip()
            file.unlink(missing_ok=True)
            return msg == "OK", msg
        time.sleep(0.5)
    return False, "No answer from Windows; check the Windows Security app."


def status(d):
    """(name, on?, note) rows from DefenderGuard's last reading."""
    if not d:
        return []
    return [
        ("Real-time protection", d["rt"], "Checks every file as it is opened"),
        ("Behaviour monitoring", d["bm"], "Watches what programs do"),
        ("Tamper protection", d["tp"], "Stops malware switching Defender off"),
        ("Unwanted-app blocking", d["pua"] == 1, "Adware and bundled junk"),
        ("Network protection", d["np"] == 1, "Blocks known bad sites in every program"),
        ("Strong cloud blocking", d["cloud"] >= 2, "Blocks brand-new threats sooner"),
        ("Attack-surface rules", d["asr"] >= len(BLOCK), f"{d['asr']} of {len(BLOCK) + len(AUDIT)} rules set"),
        ("Protected folders", d["cfa"] in (1, 2), {0: "Off", 1: "Blocking", 2: "Logging only, so your games and builds keep working"}.get(d["cfa"], "Custom")),
        *[(layer, all(reg_read(k, n) == v for l, k, n, v in REG if l == layer), note) for layer, note in REG_NOTES.items()],
        ("Windows tools cut off from the web", firewall_on(), ", ".join(NO_NET)),
        ("Strict mode", bool(d.get("strict")), "Blocks programs that are new and rare worldwide. Optional: it can block your own builds"),
        ("Dangerous-site blocking (Quad9)", quad9_on(), "Blocks known malware and phishing sites in every browser and app. Use the button below"),
        ("Secure Boot", reg_read(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") == 1, "Stops rootkits that load before Windows"),
        ("Memory integrity", bool(d.get("hvci")), "Stops rootkits inside Windows. By hand: turn on virtualization (SVM or VT-x) in the BIOS, then Windows Security > Core isolation"),
    ]
