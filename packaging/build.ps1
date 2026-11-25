# Builds dist\Bastion and the installer:  powershell -ExecutionPolicy Bypass -File packaging\build.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if (-not (Test-Path .buildenv)) { python -m venv .buildenv }
$py = "$root\.buildenv\Scripts\python.exe"
& $py -m pip install --quiet --only-binary :all: -r requirements.txt pyinstaller==6.22.3
if ($LASTEXITCODE) { throw 'pip failed' }
$ver = [regex]::Match((Get-Content bastion\core.py -Raw), 'VERSION = "([0-9.]+)"').Groups[1].Value
$n = (($ver -split '\.') + '0') -join ','
@"
VSVersionInfo(ffi=FixedFileInfo(filevers=($n), prodvers=($n), mask=0x3f, flags=0, OS=0x40004, fileType=1, subtype=0, date=(0,0)),
 kids=[StringFileInfo([StringTable('040904B0', [StringStruct('CompanyName','Bastion project'), StringStruct('FileDescription','Bastion PC guard'),
 StringStruct('FileVersion','$ver'), StringStruct('ProductName','Bastion'), StringStruct('ProductVersion','$ver'), StringStruct('OriginalFilename','Bastion.exe')])]),
 VarFileInfo([VarStruct('Translation',[1033,1200])])])
"@ | Out-File -Encoding utf8 packaging\version.txt
# One folder, no packer, no self-extraction to Temp: starts faster, and antivirus programs distrust the other ways.
$skip = 'tkinter','numpy','PySide6.QtNetwork','PySide6.QtQml','PySide6.QtQuick','PySide6.QtPdf','PySide6.QtWebEngineCore' | ForEach-Object { '--exclude-module', $_ }
$ErrorActionPreference = 'Continue'    # PyInstaller reports progress on the error stream
& $py -m PyInstaller --noconfirm --clean --log-level ERROR --windowed --onedir --noupx --name Bastion --icon bastion.ico --version-file packaging\version.txt --distpath dist --workpath build @skip main.py
if ($LASTEXITCODE) { throw 'PyInstaller failed' }
$ErrorActionPreference = 'Stop'
Copy-Item README.md, PRIVACY.md, THIRD-PARTY.md dist\Bastion\
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" | Where-Object { Test-Path $_ } | Select-Object -First 1
& $iscc /Qp "/DAppVer=$ver" packaging\bastion.iss
if ($LASTEXITCODE) { throw 'Inno Setup failed' }
$out = "dist\Bastion-Setup-$ver.exe"
"$((Get-FileHash $out).Hash.ToLower())  $(Split-Path $out -Leaf)" | Out-File -Encoding ascii "$out.sha256"
Get-Item $out | ForEach-Object { "$($_.Name) $([int]($_.Length / 1MB)) MB" }
