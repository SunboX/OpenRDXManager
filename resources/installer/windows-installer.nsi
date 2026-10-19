; SPDX-FileCopyrightText: 2015 Loopline Systems
; SPDX-FileCopyrightText: 2026 André Fiedler
; SPDX-License-Identifier: MIT
; Derived from electron-builder 26.17.0; local modifications select protected
; temporary storage before plugins and produce the native verified uninstaller.
;
; The MIT License (MIT)
;
; Copyright (c) 2015 Loopline Systems
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.
;

!ifndef INSTALL_MODE_PER_ALL_USERS
  !error "OpenRDX requires per-machine installation"
!endif
!ifdef ONE_CLICK
  !error "OpenRDX requires the assisted installer lifecycle"
!endif
!ifdef APP_PACKAGE_URL
  !error "OpenRDX requires its complete embedded administrator-selected payload"
!endif
!ifdef APP_32
  !ifdef APP_64
    !error "OpenRDX requires one architecture per installer"
  !endif
  !ifdef APP_ARM64
    !error "OpenRDX requires one architecture per installer"
  !endif
!endif
!ifdef APP_64
  !ifdef APP_ARM64
    !error "OpenRDX requires one architecture per installer"
  !endif
!endif

Var newStartMenuLink
Var oldStartMenuLink
Var newDesktopLink
Var oldDesktopLink
Var oldShortcutName
Var oldMenuDirectory
Var appExe
Var launchLink

!include "common.nsh"
; Keep diagnostics inspectable after a failure dialog is dismissed. The common
; template otherwise permanently hides this view, including the aborted page.
ShowInstDetails show
!include "MUI2.nsh"
!include "multiUser.nsh"
!include "${BUILD_RESOURCES_DIR}\windows-process-control.nsh"

; Both the installer and separately compiled remover require administrator admission.
RequestExecutionLevel admin
; PnP instance security can remain cached until the dock is re-enumerated.
!define MUI_FINISHPAGE_TEXT "OpenRDXManager has been installed.$\r$\n$\r$\nReconnect the RDX dock's USB cable after setup so Windows applies its device permissions. Then click Retry service and Scan in OpenRDXManager."
!include "assistedInstaller.nsh"
!insertmacro addLangs

!ifmacrodef customHeader
  !insertmacro customHeader
!endif

Function .onInit
  ; Use protected installation ancestors before the first possible plugin call.
  UnsafeStrCpy $TEMP "C:\Program Files"
  Call setInstallSectionSpaceRequired
  ; Never create a caller-selected /D destination before fixed native preflight.
  SetOutPath $TEMP
  ${LogSet} on
  !ifmacrodef preInit
    !insertmacro preInit
  !endif
  !ifdef DISPLAY_LANG_SELECTOR
    !insertmacro MUI_LANGDLL_DISPLAY
  !endif
  !insertmacro check64BitAndSetRegView
  ${IfNot} ${UAC_IsInnerInstance}
    !insertmacro ALLOW_ONLY_ONE_INSTALLER_INSTANCE
  ${EndIf}
  !insertmacro initMultiUser
  !insertmacro customInit
  !ifmacrodef addLicenseFiles
    InitPluginsDir
    !insertmacro addLicenseFiles
  !endif
FunctionEnd

!include "installUtil.nsh"
Section "install" INSTALL_SECTION_ID
  !include "${BUILD_RESOURCES_DIR}\windows-install-section.nsh"
SectionEnd

Function setInstallSectionSpaceRequired
  !insertmacro setSpaceRequired ${INSTALL_SECTION_ID}
FunctionEnd
