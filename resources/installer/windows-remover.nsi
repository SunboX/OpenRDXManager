; SPDX-FileCopyrightText: 2026 André Fiedler
; SPDX-License-Identifier: AGPL-3.0-or-later

; This is a NORMAL installer entrypoint used only for removal. An NSIS Uninstall
; section would self-copy through caller TEMP before un.onInit can protect it.
Unicode true
Name "Remove OpenRDXManager"
Caption "Remove OpenRDXManager"
BrandingText "OpenRDXManager ${VERSION}"
OutFile "${OUTPUT_FILE}"
RequestExecutionLevel admin
InstallButtonText "Remove"
ShowInstDetails show
!include "LogicLib.nsh"
!include "x64.nsh"
!include "MUI2.nsh"
!include "${BUILD_RESOURCES_DIR}\windows-service.nsh"
!define INSTALL_REGISTRY_KEY "Software\${APP_GUID}"
!define UNINSTALL_REGISTRY_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}"
!define MUI_WELCOMEPAGE_TITLE "Remove OpenRDXManager"
!define MUI_WELCOMEPAGE_TEXT "This removes OpenRDXManager and its hardware service. Your saved records and personal application data are preserved. Close Manager before continuing."
!define MUI_FINISHPAGE_TITLE "OpenRDXManager removed"
!define MUI_FINISHPAGE_TEXT "Your saved records and personal application data were preserved."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ; Use protected installation ancestors before the first possible plugin call.
  UnsafeStrCpy $TEMP "C:\Program Files"
  StrCpy $INSTDIR "${OPENRDX_FIXED_ROOT}"
  SetOutPath $TEMP
  SetShellVarContext all
  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}
  ; Native ownership and quiescence precede every process or filesystem action.
  !insertmacro OpenRDXPrepareRemoval
  nsExec::ExecToStack `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$$p=@(Get-CimInstance Win32_Process -Filter $\"Name='OpenRDXManager.exe'$\" | Where-Object { -not $$_.ExecutablePath -or $$_.ExecutablePath -eq '${OPENRDX_FIXED_ROOT}\OpenRDXManager.exe' }); if($$p.Count -ne 0){exit 3}"`
  Pop $0
  Pop $1
  ${If} $0 != 0
    !insertmacro OpenRDXFail "removal-manager-process" "$0" "Close OpenRDXManager, then run removal again."
  ${EndIf}
FunctionEnd

Section "Remove OpenRDXManager"
  ; Failure preserves files, registry entries, shortcuts and personal data.
  !insertmacro customUnInstall
  SetOutPath $TEMP
  ; The running remover cannot delete its own mapped image. NSIS schedules only
  ; remaining fixed-runtime files for reboot; upgrade's protected copy can remove
  ; the old tree immediately. Application data outside this root is never visited.
  RMDir /r /REBOOTOK "${OPENRDX_FIXED_ROOT}"
  ; Only this running image may remain pending reboot. Other payload failures
  ; retain registry discovery and durable native history for repair/retry.
  IfFileExists "${OPENRDX_FIXED_ROOT}\*.*" 0 removal_files_complete
  StrCmp $EXEPATH "${OPENRDX_FIXED_ROOT}\Uninstall OpenRDXManager.exe" 0 removal_files_failed
  FindFirst $R0 $R1 "${OPENRDX_FIXED_ROOT}\*.*"
  removal_remaining_next:
    StrCmp $R1 "" removal_remaining_done
    StrCmp $R1 "." removal_remaining_skip
    StrCmp $R1 ".." removal_remaining_skip
    StrCmp $R1 "Uninstall OpenRDXManager.exe" removal_remaining_skip
    FindClose $R0
    Goto removal_files_failed
  removal_remaining_skip:
    FindNext $R0 $R1
    Goto removal_remaining_next
  removal_remaining_done:
    FindClose $R0
    IfRebootFlag removal_files_complete removal_files_failed
  removal_files_failed:
    !insertmacro OpenRDXFail "removal-files" "3" "Some application files could not be removed. Run the installer Repair action, then retry removal. Your saved records were preserved."
  removal_files_complete:
  Delete "$DESKTOP\OpenRDXManager.lnk"
  Delete "$SMPROGRAMS\OpenRDXManager.lnk"
  DeleteRegKey HKLM "${UNINSTALL_REGISTRY_KEY}"
  DeleteRegKey HKLM "${INSTALL_REGISTRY_KEY}"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
SectionEnd
