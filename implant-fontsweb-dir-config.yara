rule implant_fontsweb_dir_config : T1036_005 T1564_001 {
    meta:
        author = "Arnold Chan"
        description = "Detects files referencing malicious implant install paths under C:\\Windows\\Fonts\\web used to blend with legitimate system files"
        false_positive = "Generic single-word config keys (host_ini, host_exe, install_dir) no longer satisfy the condition alone paired with a path string — they must all three co-occur, or the more specific WpnUserHost service name/display name must be present, since those keys are common in unrelated legitimate installer configs"
strings:
        $path1 = "C:\\Windows\\Fonts\\web\\fonthost.exe" ascii wide nocase
        $path2 = "C:\\Windows\\Fonts\\web\\web.ini" ascii wide nocase
        $path3 = "C:\\\\Windows\\\\Fonts\\\\web" ascii wide nocase
        $svc_name = "WpnUserHost" ascii wide
        $svc_disp = "Windows Push Notifications User Host" ascii wide
        $host_ini_key = "host_ini" ascii wide
        $host_exe_key = "host_exe" ascii wide
        $install_dir_key = "install_dir" ascii wide

    condition:
        any of ($path*) and ($svc_name or $svc_disp or ($host_exe_key and $host_ini_key and $install_dir_key))
}