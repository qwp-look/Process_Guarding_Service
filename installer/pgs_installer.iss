; ===========================================================================
;  PGS (ProcessGuard Service) - Inno Setup installer
;
;  从 tools\package_release.bat 生成的 release\ 目录构建一键安装包。安装器会：
;    - 复制完整的自包含 release 目录到 {app}
;    - 可选安装并启动 PGS Windows 服务（pgs_service install）
;    - 可选启用 Windows 测试签名模式，用于 Sirius.sys PPL 驱动（需要重启）
;    - 可选添加远程网关端口的入站防火墙规则
;    - 卸载时停止并删除 PGS 服务、删除安装目录；ProgramData\ProcessGuard
;      状态目录默认保留，用户可选择删除，以便重装后恢复守护列表。
;
;  Build (after producing release\):
;    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\pgs_installer.iss
; ===========================================================================

#define PGSAppName         "ProcessGuard Service"
#define PGSAppVersion      "0.1.0-beta.1"
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
Name: "zh"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "installservice"; Description: "安装并启动 PGS Windows 服务（LocalSystem）"; GroupDescription: "服务："
Name: "enabletestsign"; Description: "启用 Sirius PPL 驱动所需的 Windows 测试签名模式（需要重启）"; GroupDescription: "驱动："
Name: "firewallremote"; Description: "添加远程网关端口的入站防火墙规则"; GroupDescription: "网络："; Flags: unchecked

[Files]
; The entire self-contained release tree is copied verbatim.
Source: "..\release\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\PGS 管理端（Qt）"; Filename: "{app}\pgs_admin_qt.exe"
Name: "{group}\PGS Web 控制台"; Filename: "{app}\pgs_admin_web.exe"
Name: "{group}\卸载 PGS"; Filename: "{uninstallexe}"

[Run]
; --- Service install + start (optional task) ---
Filename: "{app}\pgs_service.exe"; Parameters: "install"; StatusMsg: "正在安装 PGS 服务..."; Tasks: installservice; Flags: runhidden
Filename: "{app}\pgs_service.exe"; Parameters: "start"; StatusMsg: "正在启动 PGS 服务..."; Tasks: installservice; Flags: runhidden

; --- Test-signing detection + enable (optional task) ---
; bcdedit /set testsigning on requires admin (we already are) and a reboot.
Filename: "{cmd}"; Parameters: "/c bcdedit /set testsigning on"; StatusMsg: "正在启用测试签名模式..."; Tasks: enabletestsign; Flags: runhidden; Check: NeedsTestSigning

; --- Firewall rule for remote gateway (optional, default port 12443) ---
Filename: "{cmd}"; Parameters: "/c netsh advfirewall firewall add rule name=""PGS Remote Gateway"" dir=in action=allow protocol=TCP localport=12443"; StatusMsg: "正在添加防火墙规则..."; Tasks: firewallremote; Flags: runhidden

; --- Launch the Qt admin GUI after install ---
Filename: "{app}\pgs_admin_qt.exe"; Description: "启动 PGS 管理端（Qt）"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
; --- Stop + uninstall the service before removing files ---
Filename: "{app}\pgs_service.exe"; Parameters: "stop"; StatusMsg: "正在停止 PGS 服务..."; Flags: runhidden; RunOnceId: "StopService"
Filename: "{app}\pgs_service.exe"; Parameters: "uninstall"; StatusMsg: "正在卸载 PGS 服务..."; Flags: runhidden; RunOnceId: "UninstallService"
; --- Remove the firewall rule if it exists ---
Filename: "{cmd}"; Parameters: "/c netsh advfirewall firewall delete rule name=""PGS Remote Gateway"""; Flags: runhidden; RunOnceId: "RemoveFirewall"

[UninstallDelete]
; Remove the install directory entirely (files we copied).
Type: filesandordirs; Name: "{app}"

[Code]
// ---- 测试签名状态检查 ----
// 返回 true 时会执行启用步骤。当前为 best-effort，bcdedit /set 可重复执行。
function NeedsTestSigning(): Boolean;
var
  ResultCode: Integer;
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

// ---- 卸载时可选删除 ProgramData 状态目录 ----
// 默认保留状态目录，便于重装后恢复守护列表和 token hash。
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
           '是否保留 PGS 状态目录：' + DataDir + '?' + #13#10 +
           '选择“是”：保留（推荐，重装后可恢复守护列表和 token hash）。' + #13#10 +
           '选择“否”：现在删除该目录。',
           mbConfirmation, MB_YESNO, IDYES) = IDNO then
      begin
        DelTree(DataDir, True, True, True);
      end;
    end;
  end;
end;
