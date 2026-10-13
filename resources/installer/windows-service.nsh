; SPDX-FileCopyrightText: 2026 André Fiedler
; SPDX-License-Identifier: AGPL-3.0-or-later

; Local installation has one native trust root. The elevated native provisioner
; independently proves all roots, runtime contents, SCM configuration and PID.
; The one checksum-pinned archive identifies its Windows compiler as v3.12
; and its macOS/Linux builds as the exact CVS revision below.
!if "${NSIS_VERSION}" != "v23-May-2026.cvs"
  !if "${NSIS_VERSION}" != "v3.12"
    !error "OpenRDX setup requires the checksum-pinned NSIS bundle 1.2.1 compiler"
  !endif
!endif

!include "StrFunc.nsh"
${StrStr}

; Never forward arbitrary helper output: reconstruct only closed native tokens.
!macro OpenRDXNativeFail STAGE MESSAGE
  StrCpy $R4 "unknown"
  StrCpy $R3 "unknown"
  ${StrStr} $R5 "$1" "phase=entrypoint reason="
  ${If} $R5 != ""
    StrCpy $R3 "entrypoint"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=UnsupportedPlatform"
  ${If} $R5 != ""
    StrCpy $R4 "UnsupportedPlatform"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=InvalidRequest"
  ${If} $R5 != ""
    StrCpy $R4 "InvalidRequest"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=AccessDenied"
  ${If} $R5 != ""
    StrCpy $R4 "AccessDenied"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=Busy"
  ${If} $R5 != ""
    StrCpy $R4 "Busy"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=ReadOnly"
  ${If} $R5 != ""
    StrCpy $R4 "ReadOnly"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=Cancelled"
  ${If} $R5 != ""
    StrCpy $R4 "Cancelled"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=TimedOut"
  ${If} $R5 != ""
    StrCpy $R4 "TimedOut"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=DeviceRemoved"
  ${If} $R5 != ""
    StrCpy $R4 "DeviceRemoved"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=NoMedia"
  ${If} $R5 != ""
    StrCpy $R4 "NoMedia"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=EnumerationFailed"
  ${If} $R5 != ""
    StrCpy $R4 "EnumerationFailed"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=EvidenceIncomplete"
  ${If} $R5 != ""
    StrCpy $R4 "EvidenceIncomplete"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=ResourceLimit"
  ${If} $R5 != ""
    StrCpy $R4 "ResourceLimit"
  ${EndIf}
  ${StrStr} $R5 "$1" "reason=Other"
  ${If} $R5 != ""
    StrCpy $R4 "Other"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=fresh-root reason="
  ${If} $R5 != ""
    StrCpy $R3 "fresh-root"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=incoming-source reason="
  ${If} $R5 != ""
    StrCpy $R3 "incoming-source"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=empty-root reason="
  ${If} $R5 != ""
    StrCpy $R3 "empty-root"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=existing-data reason="
  ${If} $R5 != ""
    StrCpy $R3 "existing-data"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=create-data reason="
  ${If} $R5 != ""
    StrCpy $R3 "create-data"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=revoke-enrollment reason="
  ${If} $R5 != ""
    StrCpy $R3 "revoke-enrollment"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=persist-intent reason="
  ${If} $R5 != ""
    StrCpy $R3 "persist-intent"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=create-runtime reason="
  ${If} $R5 != ""
    StrCpy $R3 "create-runtime"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=service-configuration reason="
  ${If} $R5 != ""
    StrCpy $R3 "service-configuration"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=service-owner reason="
  ${If} $R5 != ""
    StrCpy $R3 "service-owner"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=service-quiescence reason="
  ${If} $R5 != ""
    StrCpy $R3 "service-quiescence"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=service-sid reason="
  ${If} $R5 != ""
    StrCpy $R3 "service-sid"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=installed-runtime reason="
  ${If} $R5 != ""
    StrCpy $R3 "installed-runtime"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=manager-access reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-access"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=device-access reason="
  ${If} $R5 != ""
    StrCpy $R3 "device-access"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=commit-enrollment reason="
  ${If} $R5 != ""
    StrCpy $R3 "commit-enrollment"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=verify-enrollment reason="
  ${If} $R5 != ""
    StrCpy $R3 "verify-enrollment"
  ${EndIf}
  ; Specific runtime checkpoints override their enclosing installed-runtime token.
  ${StrStr} $R5 "$1" "phase=runtime-ancestors reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-ancestors"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=runtime-open reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-open"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=runtime-protection reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-protection"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=runtime-pinning reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-pinning"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=runtime-manifest reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-manifest"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=runtime-inventory reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-inventory"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=runtime-artifacts reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-artifacts"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=runtime-history reason="
  ${If} $R5 != ""
    StrCpy $R3 "runtime-history"
  ${EndIf}
  ; Specific manager checkpoints override enclosing manager-access diagnostics.
  ${StrStr} $R5 "$1" "phase=manager-runtime reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-runtime"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=manager-process reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-process"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=manager-user reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-user"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=manager-configuration reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-configuration"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=manager-dacl reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-dacl"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=manager-registry reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-registry"
  ${EndIf}
  ${StrStr} $R5 "$1" "phase=manager-revalidation reason="
  ${If} $R5 != ""
    StrCpy $R3 "manager-revalidation"
  ${EndIf}
  !insertmacro OpenRDXFail "${STAGE}" "$0" "${MESSAGE} native-phase=$R3 native-reason=$R4"
!macroend

; All denials fail closed in both assisted and silent setup. The fixed stage and
; native exit code go to inherited stderr, so automation can diagnose a GUI PE.
; Callers provide only fixed public errors and allowlisted native tokens.
!macro OpenRDXFail STAGE CODE MESSAGE
  StrCpy $R7 "OpenRDX setup failure: stage=${STAGE} code=${CODE} ${MESSAGE}$\r$\n"
  DetailPrint "$R7"
  System::Call 'kernel32::WideCharToMultiByte(i 65001, i 0, w R7, i -1, p 0, i 0, p 0, p 0)i .R8'
  ${If} $R8 > 0
    System::Alloc $R8
    Pop $R9
    ${If} $R9 != 0
      System::Call 'kernel32::WideCharToMultiByte(i 65001, i 0, w R7, i -1, p R9, i R8, p 0, p 0)i .R8'
      ${If} $R8 > 0
        IntOp $R8 $R8 - 1
        System::Call 'kernel32::GetStdHandle(i -12)p .R6'
        System::Call 'kernel32::WriteFile(p R6, p R9, i R8, *i .R6, p 0)i .R6'
      ${EndIf}
      System::Free $R9
    ${EndIf}
  ${EndIf}
  ${IfNot} ${Silent}
    MessageBox MB_ICONSTOP "$R7"
  ${EndIf}
  SetErrorLevel 3
  Abort
!macroend

; NSIS 3.12 atomically creates $PLUGINSDIR below the fixed Program Files parent
; with a Builtin Administrators owner. Windows Temp can grant Users full control.
; Its initial Everyone grant permits child deletion, so remove that grant before
; extracting any incoming executable or inventory. System.dll is already loaded
; when this call runs; ordinary users cannot add files to the initial directory.
!macro OpenRDXProtectIncomingSource
  InitPluginsDir
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;LS)(A;OICI;FRFX;;;BU)", i 1, *p .r0, p 0)i .r1'
  ${If} $1 == 0
    !insertmacro OpenRDXFail "source-policy" "$1" "OpenRDX setup could not create protected incoming source policy."
  ${EndIf}
  System::Call 'advapi32::SetFileSecurityW(w "$PLUGINSDIR", i 0x80000005, p r0)i .r1'
  System::Call 'kernel32::LocalFree(p r0)p .r0'
  ${If} $1 == 0
    !insertmacro OpenRDXFail "source-protection" "$1" "OpenRDX setup could not protect its incoming source directory."
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
    !insertmacro OpenRDXNativeFail "prepare" "OpenRDX setup cannot replace the active or unverified hardware service. Close Manager, wait for all hardware operations to finish, and retry."
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
    ; Single-quoted PowerShell predicates survive Windows argument parsing.
    ; Nested raw double quotes would strip WQL literals and make every query fail.
    nsExec::ExecToStack `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$$p=@(Get-CimInstance Win32_Process | Where-Object { $$_.Name -eq 'OpenRDXManager.exe' -and $$_.ExecutablePath -eq '${OPENRDX_FIXED_ROOT}\OpenRDXManager.exe' -and $$_.CommandLine -notmatch '--type=' }); if($$p.Count -eq 1){[Console]::Write($$p[0].ProcessId)}else{exit 3}"`
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
    !insertmacro OpenRDXFail "manager-process" "$0" "OpenRDX setup is incomplete. Launch C:\Program Files\OpenRDXManager\OpenRDXManager.exe as the active console user, then run this installer again. No arbitrary user or account has been enrolled."
  openrdx_manager_found:
  nsExec::ExecToStack '"${OPENRDX_PROVISIONER}" --action install --manager-process-id $R2'
  Pop $0
  Pop $1
  ${If} $0 != 0
    !insertmacro OpenRDXNativeFail "install" "OpenRDX setup is incomplete."
  ${EndIf}
  nsExec::ExecToStack '"${OPENRDX_PROVISIONER}" --action verify --manager-process-id $R2'
  Pop $0
  Pop $1
  ${If} $0 != 0
    !insertmacro OpenRDXNativeFail "verify" "OpenRDX installed trust verification failed. Run the installer again with the installed Manager open."
  ${EndIf}
!macroend

!macro OpenRDXPrepareRemoval
  !insertmacro OpenRDXProtectIncomingSource
  File /oname=$PLUGINSDIR\openrdx-local-install.exe "${BUILD_RESOURCES_DIR}\..\..\out\native\windows\openrdx-local-install.exe"
  nsExec::ExecToStack '"$PLUGINSDIR\openrdx-local-install.exe" --action prepare'
  Pop $0
  Pop $1
  ${If} $0 != 0
    !insertmacro OpenRDXNativeFail "removal-prepare" "OpenRDX removal is waiting for the verified hardware service to quiesce. Close Manager and finish hardware operations, then retry."
  ${EndIf}
!macroend

!macro customUnInstall
  nsExec::ExecToStack '"$PLUGINSDIR\openrdx-local-install.exe" --action remove'
  Pop $0
  Pop $1
  ${If} $0 != 0
    !insertmacro OpenRDXNativeFail "remove" "OpenRDX removal refused an unverified service or policy. Existing runtime files were preserved."
  ${EndIf}
!macroend
