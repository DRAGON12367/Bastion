; Installs into Program Files, where programs without administrator rights cannot tamper with it.
[Setup]
AppId={{7C1B4B0E-5E0B-4D0B-9C5C-2B6E1BA5710A}
AppName=Bastion
AppVersion={#AppVer}
AppPublisher=Bastion project
DefaultDirName={autopf}\Bastion
DisableProgramGroupPage=yes
PrivilegesRequired=admin
MinVersion=10.0.17763
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=Bastion-Setup-{#AppVer}
SetupIconFile=..\bastion.ico
UninstallDisplayIcon={app}\Bastion.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
RestartApplications=no
VersionInfoVersion={#AppVer}

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "pt"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\Bastion\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Bastion"; Filename: "{app}\Bastion.exe"
Name: "{autodesktop}\Bastion"; Filename: "{app}\Bastion.exe"; Tasks: desktop

[Tasks]
Name: desktop; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Run]
; as the person who started the installer, so automatic start is set up for them and not for the administrator
Filename: "{app}\Bastion.exe"; Description: "{cm:LaunchProgram,Bastion}"; Flags: postinstall nowait runasoriginaluser skipifsilent
; after an automatic (silent) update, start Bastion again for the person who approved it
Filename: "{app}\Bastion.exe"; Parameters: "--tray"; Flags: nowait runasoriginaluser; Check: WizardSilent

[UninstallRun]
Filename: "{app}\Bastion.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "traces"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
  if FileExists(ExpandConstant('{app}\Bastion.exe')) then
  begin
    Exec(ExpandConstant('{app}\Bastion.exe'), '--stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
    Sleep(2500);
  end;
  Result := '';
end;
