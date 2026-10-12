; SPDX-FileCopyrightText: 2026 André Fiedler
; SPDX-License-Identifier: AGPL-3.0-or-later

; Local installation has one native trust root. The elevated native provisioner
; independently proves all roots, runtime contents, SCM configuration and PID.
!if "${NSIS_VERSION}" != "v23-May-2026.cvs"
  !error "OpenRDX setup requires the checksum-pinned NSIS bundle 1.2.1 compiler"
!endif

; NSIS 3.12 atomically creates $PLUGINSDIR with a Builtin Administrators owner.
; Its initial Everyone grant permits child deletion, so remove that grant before
; extracting any incoming executable or inventory. System.dll is already loaded
; when this call runs; ordinary users cannot add files to the initial directory.
!macro OpenRDXProtectIncomingSource
  InitPluginsDir
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;LS)(A;OICI;FRFX;;;BU)", i 1, *p .r0, p 0)i .r1'
  ${If} $1 == 0
    MessageBox MB_ICONSTOP "OpenRDX setup could not create protected incoming source policy."
    Abort
  ${EndIf}
  System::Call 'advapi32::SetFileSecurityW(w "$PLUGINSDIR", i 0x80000005, p r0)i .r1'
  System::Call 'kernel32::LocalFree(p r0)p .r0'
  ${If} $1 == 0
    MessageBox MB_ICONSTOP "OpenRDX setup could not protect its incoming source directory."
    Abort
  ${EndIf}
!macroend

!define OPENRDX_FIXED_ROOT "C:\Program Files\OpenRDXManager"
!define OPENRDX_PROVISIONER "${OPENRDX_FIXED_ROOT}\resources\native\windows\openrdx-local-install.exe"

!macro customInit
  StrCpy $INSTDIR "${OPENRDX_FIXED_ROOT}"
  ; Extract the incoming administrator-selected native preflight before any
  ; payload writes. Missing or damaged old provisioners never skip ownership.
  !insertmacro OpenRDXProtectIncomingSource
  File /oname=$PLUGINSDIR\openrdx-local-install.exe "${BUILD_RESOURCES_DIR}\..\..\out\native\windows\openrdx-local-install.exe"
  File /oname=$PLUGINSDIR\pending-runtime.json "${BUILD_RESOURCES_DIR}\..\..\out\nsis-local-trust\pending-runtime.json"
  nsExec::ExecToStack '"$PLUGINSDIR\openrdx-local-install.exe" --action prepare'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "OpenRDX setup cannot replace the active or unverified hardware service. Close Manager, wait for all hardware operations to finish, and retry. $1"
    Abort
  ${EndIf}
!macroend

!macro customInstall
  ; The shell launches the installed Manager using the interactive user's
  ; unelevated token. The installer never runs Electron with administrator rights.
  ${StdUtils.ExecShellAsUser} $0 "${OPENRDX_FIXED_ROOT}\OpenRDXManager.exe" "open" ""
  ${If} $0 != "ok"
    DetailPrint "Launch the installed Manager as the active console user to complete setup."
  ${EndIf}
  StrCpy $R3 0
  openrdx_manager_retry:
    nsExec::ExecToStack `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$$p=@(Get-CimInstance Win32_Process -Filter $\"Name='OpenRDXManager.exe'$\" | Where-Object { $$_.ExecutablePath -eq '${OPENRDX_FIXED_ROOT}\OpenRDXManager.exe' -and $$_.CommandLine -notmatch '--type=' }); if($$p.Count -eq 1){[Console]::Write($$p[0].ProcessId)}else{exit 3}"`
    Pop $0
    Pop $R2
    ${If} $0 == 0
      Goto openrdx_manager_found
    ${EndIf}
    IntOp $R3 $R3 + 1
    ${If} $R3 < 20
      Sleep 250
      Goto openrdx_manager_retry
    ${EndIf}
    MessageBox MB_ICONSTOP "OpenRDX setup is incomplete. Launch C:\Program Files\OpenRDXManager\OpenRDXManager.exe as the active console user, then run this installer again. No arbitrary user or account has been enrolled."
    Abort
  openrdx_manager_found:
  nsExec::ExecToStack '"${OPENRDX_PROVISIONER}" --action install --manager-process-id $R2'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "OpenRDX setup is incomplete. $1"
    Abort
  ${EndIf}
  nsExec::ExecToStack '"${OPENRDX_PROVISIONER}" --action verify --manager-process-id $R2'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "OpenRDX installed trust verification failed. Run the installer again with the installed Manager open. $1"
    Abort
  ${EndIf}
!macroend

!macro OpenRDXPrepareRemoval
  !insertmacro OpenRDXProtectIncomingSource
  File /oname=$PLUGINSDIR\openrdx-local-install.exe "${BUILD_RESOURCES_DIR}\..\..\out\native\windows\openrdx-local-install.exe"
  nsExec::ExecToStack '"$PLUGINSDIR\openrdx-local-install.exe" --action prepare'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "OpenRDX removal is waiting for the verified hardware service to quiesce. Close Manager and finish hardware operations, then retry. $1"
    Abort
  ${EndIf}
!macroend

!macro customUnInstall
  nsExec::ExecToStack '"$PLUGINSDIR\openrdx-local-install.exe" --action remove'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "OpenRDX removal refused an unverified service or policy. Existing runtime files were preserved. $1"
    Abort
  ${EndIf}
!macroend
