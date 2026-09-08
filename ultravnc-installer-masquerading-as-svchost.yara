rule ultravnc_installer_masquerading_as_svchost {
    meta:
        author = "Arnold Chan"
        description = "Detects PyInstaller-built UltraVNC installer renamed to svchost.exe and staged for deployment to the non-standard C:\\Windows\\Fonts\\web directory"
        false_positive1 = "Removed the unconfirmed 'fonthost.exe' string (not present in source intel) and the generic 'winvnc' string (shared by other legitimate VNC forks) to avoid matching unrelated files"
        false_positive2 = "Now requires the specific confirmed install-directory literal (C:\\\\Windows\\\\Fonts\\\\web) rather than any one of several loosely related path fragments, narrowing matches to files that reference the exact malicious staging path"
strings:
        $_mz = { 4D 5A }

        $path1 = "C:\\Windows\\Fonts\\web" ascii wide nocase
        $path2 = "Fonts\\web\\web.ini" ascii wide nocase

        $pyinstaller1 = "pyi-runtime-tmpdir" ascii
        $pyinstaller2 = "PyInstaller" ascii wide
        $pyinstaller3 = "_MEIPASS" ascii

        $vnc1 = "UltraVNC" ascii wide nocase
        $vnc2 = "ultravnc.ini" ascii wide nocase

        $name = "svchost.exe" ascii wide nocase

    condition:
        $_mz at 0 and
        $name and
        $path1 and
        1 of ($pyinstaller*) and
        1 of ($vnc*)
}