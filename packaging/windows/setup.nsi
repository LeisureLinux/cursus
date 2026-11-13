; cursus Windows installer (NSIS)
;
; CI stages the following files next to this script before running makensis:
;   cursus.exe                  (statically linked windows/amd64 binary)
;   cursus-client.yaml
;   cursus-server.yaml
;   cursus-client-tcp.yaml
;   version.txt                 (plain-text version, used for !define via /DAPPVERSION=)
;
; Output: setup.exe in the same staging directory; CI renames it to
; cursus-<version>-setup.exe when publishing the release.

!ifndef APPVERSION
  !define APPVERSION "dev"
!endif
!define APPNAME "cursus"

Name "${APPNAME} ${APPVERSION}"
OutFile "setup.exe"
InstallDir "$PROGRAMFILES64\cursus"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "cursus.exe"

  SetOutPath "$INSTDIR\config"
  File "cursus-client.yaml"
  File "cursus-client-proxy.yaml"
  File "cursus-client-tcp.yaml"
  File "cursus-server.yaml"

  SetOutPath "$INSTDIR"
  CreateDirectory "$SMPROGRAMS\cursus"
  CreateShortcut "$SMPROGRAMS\cursus\cursus.lnk" "$INSTDIR\cursus.exe" \
    '-role client -config "$INSTDIR\config\cursus-client.yaml"'
  CreateShortcut "$DESKTOP\cursus.lnk" "$INSTDIR\cursus.exe" \
    '-role client -config "$INSTDIR\config\cursus-client.yaml"'

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\cursus" \
    "DisplayName" "cursus ${APPVERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\cursus" \
    "UninstallString" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\cursus.exe"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\config\cursus-client.yaml"
  Delete "$INSTDIR\config\cursus-client-proxy.yaml"
  Delete "$INSTDIR\config\cursus-client-tcp.yaml"
  Delete "$INSTDIR\config\cursus-server.yaml"
  RMDir "$INSTDIR\config"
  Delete "$SMPROGRAMS\cursus\cursus.lnk"
  RMDir "$SMPROGRAMS\cursus"
  Delete "$DESKTOP\cursus.lnk"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\cursus"
SectionEnd
