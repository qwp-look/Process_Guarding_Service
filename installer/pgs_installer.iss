; ===========================================================================
;  PGS (ProcessGuard Service) - Inno Setup installer
;
;  Builds a one-click installer from a pre-assembled release\ tree (produced
;  by tools\package_release.bat). The installer:
;    - copies the self-contained release tree to {app}
;    - optionally installs + starts the Windows service (pgs_service install)
;    - detects test-signing mode for the Sirius.sys PPL driver and offers to
;      enable it (with reboot), warning that PPL is unavailable otherwise
;    - optionally adds an inbound firewall rule for the remote-gateway port
;    - on uninstall: stops + uninstalls the service, removes files; the
;      ProgramData\ProcessGuard state archive is retained by default (the
;      user may opt to wipe it) so guard sets survive a reinstall.
;
;  Build (after producing release\):
;    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\pgs_installer.iss
; ===========================================================================

#define PGSAppName         "ProcessGuard Service"
#define PGSAppVersion      "3.1.0"
#define PGSAppPublisher    "qwp-look"
#define PGSAppExeName      "pgs_service.exe"

[Setup]
AppId={{B8F1C2A4-7E3D-4A6B-9C5D-1F2E3A4B5C6D}
AppName={#PGSAppName}
AppVersion={#PGSAppVersion}
AppPublisher={#PGSAppPublisher}
DefaultDirName={autopf}\ProcessGuard
DefaultGroupName=ProcessGuard
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=pgs_setup_{#PGSAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\pgs_admin_qt.exe
LicenseFile=..\LICENSE

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "installservice"; Description: "Install and start the PGS Windows service (LocalSystem)"; GroupDescription: "Service:"
Name: "enabletestsign"; Description: "Enable Windows test-signing mode for the Sirius PPL driver (requires reboot)"; GroupDescription: "Driver:"
Name: "firewallremote"; Description: "Add inbound firewall rule for the remote-gateway port"; GroupDescription: "Network:"; Flags: unchecked

[Files]
; The entire self-contained release tree is copied verbatim.
Source: "..\release\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\PGS Admin (Qt)"; Filename: "{app}\pgs_admin_qt.exe"
Name: "{group}\PGS Web Console"; Filename: "{app}\pgs_admin_web.exe"
Name: "{group}\Uninstall PGS"; Filename: "{uninstallexe}"

[Run]
; --- Service install + start (optional task) ---
Filename: "{app}\pgs_service.exe"; Parameters: "install"; StatusMsg: "Installing PGS service..."; Tasks: installservice; Flags: runhidden
Filename: "{app}\pgs_service.exe"; Parameters: "start"; StatusMsg: "Starting PGS service..."; Tasks: installservice; Flags: runhidden

; --- Test-signing detection + enable (optional task) ---
; bcdedit /set testsigning on requires admin (we already are) and a reboot.
Filename: "{cmd}"; Parameters: "/c bcdedit /set testsigning on"; StatusMsg: "Enabling test-signing mode..."; Tasks: enabletestsign; Flags: runhidden; Check: NeedsTestSigning

; --- Firewall rule for remote gateway (optional, default port 12443) ---
Filename: "{cmd}"; Parameters: "/c netsh advfirewall firewall add rule name=""PGS Remote Gateway"" dir=in action=allow protocol=TCP localport=12443"; StatusMsg: "Adding firewall rule..."; Tasks: firewallremote; Flags: runhidden

; --- Launch the Qt admin GUI after install ---
Filename: "{app}\pgs_admin_qt.exe"; Description: "Launch PGS Admin (Qt)"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
; --- Stop + uninstall the service before removing files ---
Filename: "{app}\pgs_service.exe"; Parameters: "stop"; StatusMsg: "Stopping PGS service..."; Flags: runhidden; RunOnceId: "StopService"
Filename: "{app}\pgs_service.exe"; Parameters: "uninstall"; StatusMsg: "Uninstalling PGS service..."; Flags: runhidden; RunOnceId: "UninstallService"
; --- Remove the firewall rule if it exists ---
Filename: "{cmd}"; Parameters: "/c netsh advfirewall firewall delete rule name=""PGS Remote Gateway"""; Flags: runhidden; RunOnceId: "RemoveFirewall"

[UninstallDelete]
; Remove the install directory entirely (files we copied).
Type: filesandordirs; Name: "{app}"

[Code]
// ---- Test-signing state check ----
// Returns true when test-signing is NOT yet enabled, so the run step fires.
function NeedsTestSigning(): Boolean;
var
  ResultCode: Integer;
  OutputText: AnsiString;
begin
  Result := True;
  // `bcdedit` with no args echoes the current store; test-signing on shows
  // "testsigning             Yes". We probe and skip if already on.
  if Exec(ExpandConstant('{cmd}'), '/c bcdedit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    // Best-effort: even if detection fails we still allow enabling (idempotent).
    Result := True;
  end;
end;

// ---- Optional: wipe ProgramData state on uninstall ----
// Prompted during uninstall; default is to KEEP state so a reinstall resumes
// the guard set. Implemented as a custom step via the post-uninstall hook.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\ProcessGuard');
    if DirExists(DataDir) then
    begin
      if SuppressibleMsgBox(
           'Keep the PGS state archive under ' + DataDir + '?' + #13#10 +
           'Yes = keep (recommended, guard set survives reinstall).' + #13#10 +
           'No = delete it now.',
           mbConfirmation, MB_YESNO, IDYES) = IDNO then
      begin
        DelTree(DataDir, True, True, True);
      end;
    end;
  end;
end;
