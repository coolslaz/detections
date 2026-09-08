import "pe"

rule ccproxy_installer_dropper_sfx {
    meta:
        author = "Arnold Chan"
        description = "Detects WinRAR SFX droppers deploying CCProxy proxy server with associated configuration and account files (CCProxy.ini, AccInfo.ini, renamed svchost.exe)"
        false_positive = "Legitimate installation packages of CCProxy software that use the same file naming conventions as the dropper."
strings:
        $file_ccproxy_ini = "CCProxy.ini" ascii wide nocase
        $file_accinfo_ini = "AccInfo.ini" ascii wide nocase
        $file_history_txt = "History.txt" ascii wide nocase
        $file_lefttime_ini = "LeftTime.ini" ascii wide nocase
        $file_svchost = "svchost.exe" ascii wide nocase
        $port_socks = "49661" ascii wide
        $socks_marker = "SOCKS" ascii wide nocase

        $_sfx_marker = "WINRAR" ascii wide nocase

    condition:
        (uint16(0) == 0x5A4D or $_sfx_marker) and
        3 of ($file_ccproxy_ini, $file_accinfo_ini, $file_history_txt, $file_lefttime_ini, $file_svchost) and
        ($port_socks or $socks_marker)
}