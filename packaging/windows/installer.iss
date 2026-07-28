; nzbfast Windows installer (see packaging/INSTALLER-SPEC.md, chip B).
;
; Installs to Program Files with an elevation prompt, falling back to a
; per-user install for anyone who cannot elevate.
;
; It used to install per-user into {localappdata}\Programs with no UAC,
; so that self-update could rewrite its own install directory. Self-update
; was removed in 1.0.5 (the updater only notifies now), so that constraint
; is gone - and an AppData install directory is one of the strongest
; signals Defender's ML heuristics weigh, especially with a Run-key
; pointing into it. See research/AV-false-positive-2026-07-25.md.
;
; Compile:  ISCC /DAppVersion=<x.y.z> /DStageDir=<dir> installer.iss
; where <dir> holds nzbfast.exe, nzbtray.exe, MANUAL.html, LICENSE,
; COPYRIGHT.md (see make-installer.sh, which stages
; from the mingw cross-build and pulls the version from Cargo.toml -
; the version source of truth).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef StageDir
  #define StageDir "stage"
#endif

[Setup]
; Fixed AppId so upgrades replace instead of stacking.
AppId={{72B5B673-54D7-46ED-BDDC-C7D3E571D242}
AppName=nzbfast
AppVersion={#AppVersion}
AppPublisher=nzbfast
AppPublisherURL=https://github.com/nzbfast/nzbfast
; {autopf} is Program Files under an elevated install and
; {localappdata}\Programs under a per-user one, so a single line covers
; both. An existing install is upgraded in place wherever it already
; lives (Inno reads the previous directory from the AppId registry key),
; so this does not strand anyone who installed before 1.0.9.
DefaultDirName={autopf}\nzbfast
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; "dialog" offers the per-user fallback rather than dead-ending a user
; who has no administrator password.
PrivilegesRequiredOverridesAllowed=dialog
; Ask Windows' Restart Manager to close a running nzbfast before files
; are replaced. This is the sanctioned mechanism and it is why the old
; taskkill /F pair is gone.
CloseApplications=yes
CloseApplicationsFilter=nzbtray.exe,nzbfast.exe
RestartApplications=no
OutputBaseFilename=nzbfast-{#AppVersion}-windows-x64-setup
OutputDir=out
LicenseFile={#StageDir}\LICENSE
SetupIconFile=..\icon\nzbfast.ico
UninstallDisplayIcon={app}\nzbtray.exe
UninstallDisplayName=nzbfast
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
; The tray app is 64-bit only.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Messages]
; The one scare screen an unsigned build meets, narrated where the user
; lands right after clicking through it.
WelcomeLabel2=This will install [name/ver] on your computer.%n%nnzbfast is a fresh release and not yet code-signed, so Windows SmartScreen may have shown "Windows protected your PC", and the elevation prompt will say the publisher is unknown. Both are expected while signing is set up.%n%nSetup installs into Program Files. If you have no administrator password, choose the per-user option when prompted and it will install just for you.

[Tasks]
; Off by default. Writing Run-key persistence for a brand-new unsigned
; binary in the same second it first launches is the heaviest part of the
; behaviour cluster Defender scores; leaving it to a deliberate tick (here
; or later from the tray menu) costs nothing and de-clusters it.
Name: "autostart"; Description: "Start nzbfast when Windows starts"; Flags: unchecked
Name: "desktopicon"; Description: "Create a &desktop icon"; Flags: unchecked
; .nzb association: default ON only when nothing else owns .nzb - never
; silently steal an existing handler (SABnzbd et al).
Name: "nzbassoc"; Description: "Open .nzb files with nzbfast"; Check: not NzbAssociated
Name: "nzbassoc"; Description: "Open .nzb files with nzbfast (currently handled by another app)"; Flags: unchecked; Check: NzbAssociated

[Files]
Source: "{#StageDir}\nzbfast.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\nzbtray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\MANUAL.html"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\COPYRIGHT.md"; DestDir: "{app}"; Flags: ignoreversion
; Second copy of the tray, extracted to {tmp} and run as the quit helper
; BEFORE anything is replaced - see StopNzbfast. It has to be the tray we
; are installing rather than the one on disk, because only a current tray
; knows how to stop an older one. Solid compression makes the duplicate
; almost free: it is byte-identical to the entry above.
Source: "{#StageDir}\nzbtray.exe"; Flags: dontcopy noencryption

[Icons]
Name: "{userprograms}\nzbfast\nzbfast"; Filename: "{app}\nzbtray.exe"
Name: "{userprograms}\nzbfast\User Manual"; Filename: "{app}\MANUAL.html"
Name: "{userprograms}\nzbfast\Uninstall nzbfast"; Filename: "{uninstallexe}"
Name: "{userdesktop}\nzbfast"; Filename: "{app}\nzbtray.exe"; Tasks: desktopicon

[Registry]
; These stay in HKCU rather than moving to HKA now that the default
; install elevates. Under elevation HKCU is the hive of whichever account
; approved the prompt, so if a user elevates with a DIFFERENT admin
; account these land on that account instead of theirs. Accepted: the
; symptom is only that autostart or the .nzb association did not take,
; both of which are per-user preferences the user can set again from the
; tray menu (which always runs as the real user and writes the right
; hive). The alternative, HKLM, would change the file association for
; every account on the machine, which is a bigger behaviour change than
; the bug it fixes.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "nzbfast"; ValueData: """{app}\nzbtray.exe"""; Flags: uninsdeletevalue; Tasks: autostart
; Per-user .nzb association (proper ProgID; uninstall removes our keys).
Root: HKCU; Subkey: "Software\Classes\.nzb"; ValueType: string; ValueData: "nzbfast.nzb"; Flags: uninsdeletevalue uninsdeletekeyifempty; Tasks: nzbassoc
Root: HKCU; Subkey: "Software\Classes\nzbfast.nzb"; ValueType: string; ValueData: "NZB download"; Flags: uninsdeletekey; Tasks: nzbassoc
Root: HKCU; Subkey: "Software\Classes\nzbfast.nzb\DefaultIcon"; ValueType: string; ValueData: """{app}\nzbtray.exe"",0"; Tasks: nzbassoc
Root: HKCU; Subkey: "Software\Classes\nzbfast.nzb\shell\open\command"; ValueType: string; ValueData: """{app}\nzbtray.exe"" ""%1"""; Tasks: nzbassoc

[Run]
; --open: the tray waits until the daemon answers, then opens the
; dashboard in the default browser - setup's last act lands the user in
; the web UI (the tray's own first-run heuristic stays silent on
; reinstalls/upgrades, so the flag makes it unconditional).
Filename: "{app}\nzbtray.exe"; Parameters: "--open"; Description: "Launch nzbfast (opens the dashboard)"; Flags: postinstall nowait skipifsilent

[Code]
function NzbAssociated: Boolean;
var s: string;
begin
  Result := (RegQueryStringValue(HKEY_CURRENT_USER, 'Software\Classes\.nzb', '', s) and (s <> '') and (s <> 'nzbfast.nzb'))
    or (RegQueryStringValue(HKEY_CLASSES_ROOT, '.nzb', '', s) and (s <> '') and (s <> 'nzbfast.nzb'));
end;

{ The oldest nzbtray that understands --quit. Anything below this treats
  an unknown flag as "no arguments" and does a NORMAL STARTUP, which is
  the opposite of what we asked for - see TrayUnderstandsQuit. }
#define QuitHelperSince "1.0.9"

{ Does the tray we are about to ask to quit actually know how? --quit
  landed in 1.0.9. Every earlier tray ignores unrecognised flags and
  falls through to its ordinary startup path, so running the helper
  against one of them does real damage:

    - nothing running -> it becomes a resident tray AND spawns a daemon,
      then never exits. StopNzbfast waits on it with
      ewWaitUntilTerminated, so Setup hangs on "Preparing to Install"
      forever. Worse, the daemon it just started re-locks the very files
      Setup is about to replace.
    - already running -> it hits the single-instance mutex, OPENS THE
      DASHBOARD in a browser, and exits, having stopped nothing. Setup
      then fails with "DeleteFile failed; code 5. Access is denied."

  That is 1.0.9 upgrading anyone who was on 1.0.4-1.0.8: the helper
  itself undid the Restart Manager's work and re-locked the install
  directory.

  Only the UNINSTALLER still asks this question - it can only ever run
  the tray sitting next to it, so it has to know whether that one is
  new enough. Setup itself no longer runs the installed tray at all; it
  runs the one it is about to install (see StopNzbfast).

  No version info at all (a local MSVC build has no windres, so it ships
  without a VERSIONINFO resource) is treated as too old. Skipping a
  graceful quit costs a queue flush; calling it wrongly wedges Setup. }
function TrayUnderstandsQuit(const Exe: string): Boolean;
var
  Ver, MinVer: Int64;
begin
  Result := False;
  if not GetPackedVersion(Exe, Ver) then
    exit;
  if not StrToVersion('{#QuitHelperSince}', MinVer) then
    exit;
  Result := ComparePackedVersion(Ver, MinVer) >= 0;
end;

{ Ask a running nzbfast to exit cleanly, so the queue is persisted before
  we replace or remove its files.

  This delegates to `nzbtray.exe --quit`, which posts a private window
  message to the running tray; the tray then drains its daemon exactly as
  the "Quit nzbfast" menu item does. Anything the helper cannot reach is
  left to the Restart Manager (CloseApplications, set in [Setup]).

  What this deliberately no longer does: build a WinHttp COM object to
  POST the shutdown itself, and run `taskkill /F /IM` over both exes with
  the window hidden. An unsigned installer that opens a network object and
  force-terminates processes scores as defence evasion, which is a large
  part of why 1.0.8 was flagged. It was also the wrong behaviour on its
  own terms: a forced kill discarded in-flight queue state that the
  graceful path persists. }
procedure StopNzbfast;
var
  Exe: string;
  Rc: Integer;
begin
  Exe := ExpandConstant('{app}\nzbtray.exe');
  if not FileExists(Exe) then
    exit;
  if not TrayUnderstandsQuit(Exe) then
  begin
    Log('StopNzbfast: ' + Exe + ' predates --quit; not launching it.');
    exit;
  end;
  { ewWaitUntilTerminated: the helper only returns once the stack is
    gone, so file replacement cannot race it. Safe to wait unbounded
    ONLY because of the version gate above - a tray that does not know
    the flag never returns. }
  Exec(Exe, '--quit', '', SW_HIDE, ewWaitUntilTerminated, Rc);
end;

{ Setup's own stop, run before a single file is touched.

  It uses the tray FROM THIS PACKAGE, extracted to Setup's temp folder,
  never the one already installed. Two reasons:

    - a pre-1.0.9 tray does not understand --quit and answers by starting
      itself, which is the bug that made 1.0.9 unupgradable;
    - stopping an old stack takes knowledge only a current tray has. The
      Restart Manager cannot do it - it never sees either process, since
      the tray's window is message-only and the daemon has none - so the
      new helper drains the daemon through the API and then closes the
      old tray's window. Cooperative throughout: still no taskkill, still
      no network object built by the installer itself. }
procedure StopNzbfastWithBundledHelper;
var
  Rc: Integer;
begin
  ExtractTemporaryFile('nzbtray.exe');
  Exec(ExpandConstant('{tmp}\nzbtray.exe'), '--quit', '', SW_HIDE,
       ewWaitUntilTerminated, Rc);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopNzbfastWithBundledHelper;
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir, DlDir: string;
begin
  if CurUninstallStep = usUninstall then
    StopNzbfast;
  if CurUninstallStep = usPostUninstall then
  begin
    { Silent/scripted uninstalls never prompt and always KEEP data
      (observed: suppressed msgboxes can still block a headless run). }
    if UninstallSilent then
      exit;
    { Default is KEEP - deleting data/downloads must be an explicit opt-in. }
    DataDir := ExpandConstant('{localappdata}\nzbfast');
    if DirExists(DataDir) then
      if MsgBox('Also delete nzbfast''s settings, queue and index?' + #13#10
                + '(' + DataDir + ')' + #13#10#13#10
                + 'Choose No to keep them for a future reinstall.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
    { Match the tray's own choice of output folder: it keeps the
      pre-1.0.2 "Downloads\nzbfast" when that already exists, and uses
      "Downloads\nzbfast downloads" otherwise. Offering only the legacy
      name meant every install since 1.0.2 was asked about a folder it
      does not use, and never about the one it does. }
    DlDir := ExpandConstant('{%USERPROFILE}\Downloads\nzbfast');
    if not DirExists(DlDir) then
      DlDir := ExpandConstant('{%USERPROFILE}\Downloads\nzbfast downloads');
    if DirExists(DlDir) then
      if MsgBox('Also delete the downloads folder?' + #13#10
                + '(' + DlDir + ')' + #13#10#13#10
                + 'Choose No to keep your downloaded files.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DlDir, True, True, True);
  end;
end;
