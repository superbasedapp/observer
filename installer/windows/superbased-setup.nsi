; superbased-setup.nsi: the per-user Windows setup program for SuperBased
; Observer (T-920 phase 1). Built on Linux by the tag-only release workflow
; (.github/workflows/npm-release.yml, job windows_setup) with makensis:
;
;   makensis -DVERSION=v1.37.0 -DVERSION_NUMERIC=1.37.0.0 \
;     -DPAYLOAD_DIR=/path/with/observer.exe+observerw.exe \
;     -DOUTFILE=/path/superbased-observer-setup-v1.37.0-win32-x64.exe \
;     installer/windows/superbased-setup.nsi
;
; This script is a THIN SHELL. It unpacks observer.exe and observerw.exe into
; a temp folder and runs `observer setup install`, which owns the copy, the
; rename-aside upgrade of a running binary, the superbased alias, the user
; Path entry, start at sign-in and the check for another install
; (cmd/observer/setup.go, internal/setup). The uninstaller runs `observer
; setup uninstall` the same way. What stays here is what belongs to the
; installer itself: its pages, its uninstaller, the Start menu shortcut and
; the Apps and Features entry.
;
; Per user, no admin prompt: everything lands under %LOCALAPPDATA% and HKCU.
; Silent install for IT: setup.exe /S, with /NOPATH, /NOAUTOSTART,
; /NOSTARTMENU to untick an option and /FORCE to install beside another
; copy; /D=<dir> (last, unquoted) picks the folder. Silent uninstall:
; superbased-uninstall.exe /S, with /PURGE to also delete ~/.observer.
;
; Code signing (Windows wired in T-961, off until the release-signing
; environment sets OBSERVER_SIGN_AUTHENTICODE=1): define SIGN_COMMAND to sign
; both the setup program and the uninstaller it writes. The release passes
;   -DSIGN_COMMAND="${GITHUB_WORKSPACE}/scripts/codesign.sh windows %1"
; (jsign with --storetype AZUREKEYVAULT, then an osslsigncode check).
; makensis runs it on each output file (%1) through !finalize and
; !uninstfinalize (NSIS 3.08+). Both carry `= 0`: without a comparison
; makensis ignores the command's exit code, so a failed signature would ship
; an unsigned file on a green build (CODESIGN-3, T-940). With it, a non-zero
; exit aborts the build. Nothing here references a key or a secret.

Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma

!ifndef VERSION
  !error "pass -DVERSION=v<x.y.z> (the release tag)"
!endif
!ifndef VERSION_NUMERIC
  !error "pass -DVERSION_NUMERIC=<x.y.z.0> (four numbers, for the file properties)"
!endif
!ifndef PAYLOAD_DIR
  !error "pass -DPAYLOAD_DIR=<absolute dir holding observer.exe and observerw.exe>"
!endif
!ifndef OUTFILE
  !error "pass -DOUTFILE=<absolute path of the setup program to write>"
!endif
; Compile-time paths (files makensis reads on the build host: the license,
; the icon, the payload) use forward slashes: the release builds on Linux,
; where a backslash is not a path separator, and makensis on Windows accepts
; forward slashes too. The license and the icon are relative to THIS file's
; folder, because makensis compiles from the script's own folder (unless
; /NOCD is passed). ${__FILEDIR__} is not used: it is the folder as typed on
; the command line, relative when the release passes
; installer/windows/superbased-setup.nsi, so it would be applied twice
; ("can't open file" on icon.ico was the v1.37.0 failure). PAYLOAD_DIR and
; OUTFILE must be absolute for the same reason. Paths the installer uses at
; run time ($INSTDIR, $PLUGINSDIR, $PROFILE, registry keys) run on Windows
; and keep backslashes.
!ifndef LICENSE_FILE
  !define LICENSE_FILE "../../LICENSE"
!endif
!ifndef ICON_FILE
  !define ICON_FILE "../../icons/icon.ico"
!endif

!ifdef SIGN_COMMAND
  !finalize '${SIGN_COMMAND}' = 0
  !uninstfinalize '${SIGN_COMMAND}' = 0
!endif

!define PRODUCT       "SuperBased Observer"
!define PUBLISHER     "Gaja AI Private Limited"
!define UNINST_KEY    "Software\Microsoft\Windows\CurrentVersion\Uninstall\SuperBasedObserver"
!define SETTINGS_KEY  "Software\SuperBased\Observer"
; Must equal update.InstallerUninstallerName (internal/update/installmethod.go):
; its presence above bin\ is how the install-method table recognises a copy
; this program installed.
!define UNINSTALLER   "superbased-uninstall.exe"
!define SHORTCUT_DIR  "$SMPROGRAMS\SuperBased"
!define SHORTCUT      "${SHORTCUT_DIR}\SuperBased Observer.lnk"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "Sections.nsh"

Name "${PRODUCT}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\SuperBased\Observer"
InstallDirRegKey HKCU "${SETTINGS_KEY}" "InstallDir"
BrandingText "SuperBased ${VERSION}"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION_NUMERIC}"
VIFileVersion "${VERSION_NUMERIC}"
VIAddVersionKey "ProductName" "${PRODUCT}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT} setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright 2026 ${PUBLISHER}. Apache-2.0."

Var Force
Var Purge

!define MUI_ICON "${ICON_FILE}"
!define MUI_UNICON "${ICON_FILE}"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Install ${PRODUCT} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "SuperBased records what your AI coding tools do and what they cost, on this computer only.$\r$\n$\r$\nThis installs it for your user account. No administrator rights are needed, and nothing is sent anywhere.$\r$\n$\r$\nIf SuperBased is already installed from npm, pip or the VS Code extension, setup stops and tells you how to upgrade that copy instead."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSE_FILE}"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\bin\observerw.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "setup launch --open"
!define MUI_FINISHPAGE_RUN_TEXT "Start SuperBased and open the dashboard"
!define MUI_FINISHPAGE_LINK "Getting started guide"
!define MUI_FINISHPAGE_LINK_LOCATION "https://superbased.app/docs/getting-started/install"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ------------------------------------------------------------------ install

Section "SuperBased Observer (required)" SecCore
  SectionIn RO
  InitPluginsDir
  SetOutPath "$PLUGINSDIR\payload"
  File "/oname=observer.exe" "${PAYLOAD_DIR}/observer.exe"
  File "/oname=observerw.exe" "${PAYLOAD_DIR}/observerw.exe"
SectionEnd

; The three options are markers read by the install step below, so the Go
; command receives every choice in one call.
Section "Add to my Path (use observer in any terminal)" SecPath
SectionEnd

Section "Start SuperBased when I sign in" SecAutostart
SectionEnd

Section "Start menu shortcut" SecStartMenu
SectionEnd

Section "-Install" SecInstall
  StrCpy $0 '"$PLUGINSDIR\payload\observer.exe" setup install --exit-codes --dir "$INSTDIR\bin" --source "$PLUGINSDIR\payload\observer.exe" --observerw "$PLUGINSDIR\payload\observerw.exe"'
  ${If} ${SectionIsSelected} ${SecPath}
    StrCpy $0 "$0 --path"
  ${EndIf}
  ${If} ${SectionIsSelected} ${SecAutostart}
    StrCpy $0 "$0 --autostart"
  ${EndIf}
  ${If} $Force == "1"
    StrCpy $0 "$0 --force"
  ${EndIf}

  DetailPrint "Running observer setup install..."
  nsExec::ExecToStack $0
  Pop $1
  Pop $2
  DetailPrint "$2"

  ${If} $1 == "3"
    ${IfNot} ${Silent}
      MessageBox MB_ICONEXCLAMATION|MB_OK "$2"
    ${EndIf}
    SetErrorLevel 3
    Abort "Another SuperBased install is on this computer. Nothing was installed."
  ${ElseIf} $1 == "10"
    ${IfNot} ${Silent}
      MessageBox MB_ICONINFORMATION|MB_OK "$2"
    ${EndIf}
  ${ElseIf} $1 != "0"
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "Setup could not install SuperBased:$\r$\n$\r$\n$2"
    ${EndIf}
    SetErrorLevel 2
    Abort "observer setup install failed ($1)."
  ${EndIf}

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\${UNINSTALLER}"
  WriteRegStr HKCU "${SETTINGS_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${PRODUCT}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\bin\observer.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\${UNINSTALLER}"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\${UNINSTALLER}" /S'
  WriteRegStr HKCU "${UNINST_KEY}" "URLInfoAbout" "https://superbased.app"
  WriteRegStr HKCU "${UNINST_KEY}" "URLUpdateInfo" "https://superbased.app/download"
  WriteRegStr HKCU "${UNINST_KEY}" "HelpLink" "https://superbased.app/docs"
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $3 $4 $5
  WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize" "$3"

  ${If} ${SectionIsSelected} ${SecStartMenu}
    CreateDirectory "${SHORTCUT_DIR}"
    CreateShortcut "${SHORTCUT}" "$INSTDIR\bin\observerw.exe" "setup launch --open" "$INSTDIR\bin\observer.exe" 0
  ${EndIf}
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "The observer program, its superbased alias, and observerw.exe (starts it without a console window)."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Adds the program folder to your user Path so observer works in any new terminal."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecAutostart} "Starts SuperBased in the background when you sign in to Windows, so it records every session."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "A Start menu entry that starts SuperBased and opens the dashboard."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function .onInit
  StrCpy $Force "0"
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/FORCE" $R1
  ${IfNot} ${Errors}
    StrCpy $Force "1"
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NOPATH" $R1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecPath}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NOAUTOSTART" $R1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecAutostart}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NOSTARTMENU" $R1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecStartMenu}
  ${EndIf}
FunctionEnd

; ---------------------------------------------------------------- uninstall

Function un.onInit
  StrCpy $Purge "0"
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/PURGE" $R1
  ${IfNot} ${Errors}
    StrCpy $Purge "1"
  ${EndIf}
FunctionEnd

Section "Uninstall"
  ${IfNot} ${Silent}
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete your SuperBased data (the database and settings in $PROFILE\.observer)?$\r$\n$\r$\nChoose No to keep it for a later install." IDNO keepdata
    StrCpy $Purge "1"
    keepdata:
  ${EndIf}

  IfFileExists "$INSTDIR\bin\observer.exe" 0 removefiles
  StrCpy $0 '"$INSTDIR\bin\observer.exe" setup uninstall --exit-codes --dir "$INSTDIR\bin"'
  ${If} $Purge == "1"
    StrCpy $0 "$0 --purge"
  ${EndIf}
  DetailPrint "Running observer setup uninstall..."
  nsExec::ExecToStack $0
  Pop $1
  Pop $2
  DetailPrint "$2"

  ${If} $1 == "4"
    ${IfNot} ${Silent}
      MessageBox MB_YESNO|MB_ICONEXCLAMATION "$2$\r$\nStop SuperBased now and continue?" IDYES stopdaemon
      Abort "Uninstall cancelled; SuperBased is still running."
    ${EndIf}
    stopdaemon:
    nsExec::ExecToStack "$0 --stop-daemon"
    Pop $1
    Pop $2
    DetailPrint "$2"
  ${EndIf}

  ${If} $1 != "0"
    ${If} ${Silent}
      SetErrorLevel 2
      Abort "observer setup uninstall failed ($1)."
    ${EndIf}
    MessageBox MB_YESNO|MB_ICONSTOP "SuperBased could not undo everything:$\r$\n$\r$\n$2$\r$\nDelete the program files anyway? Hook entries that point at it will stop working until removed." IDYES removefiles
    Abort "Uninstall cancelled."
  ${EndIf}

  removefiles:
  Delete "$INSTDIR\bin\observer.exe"
  Delete "$INSTDIR\bin\superbased.exe"
  Delete "$INSTDIR\bin\observerw.exe"
  Delete "$INSTDIR\bin\*.old-*"
  RMDir "$INSTDIR\bin"
  Delete "$INSTDIR\${UNINSTALLER}"
  RMDir "$INSTDIR"
  RMDir "$LOCALAPPDATA\SuperBased"
  Delete "${SHORTCUT}"
  RMDir "${SHORTCUT_DIR}"
  DeleteRegKey HKCU "${UNINST_KEY}"
  DeleteRegKey HKCU "${SETTINGS_KEY}"
  DeleteRegKey /ifempty HKCU "Software\SuperBased"
SectionEnd
