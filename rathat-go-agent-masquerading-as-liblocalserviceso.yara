rule rathat_go_agent_masquerading_as_liblocalserviceso {
    meta:
        author = "Arnold Chan"
        description = "Detects the execution of RatHat, a Go-based Android native daemon masquerading as 'liblocal-service.so'. The rule identifies the malware's use of ADB-derived shell commands to bypass Android Doze mode, prioritize background execution, and tamper with installed applications via pm (package manager) commands."
        malware = "RatHat"
        false_positive1 = "Legitimate security auditing tools or administrative scripts that use package manager commands for authorized device management"
        false_positive2 = "Developer tools or debugging sessions that manipulate package states via ADB for legitimate testing purposes"
strings:
        $_go_build = "Go build ID:"
        $_go_buildinfo = "Go buildinf:"

        $lib_name = "liblocal-service.so" ascii
        $tmp_path = "/data/local/tmp/liblocal-service.so" ascii

        $cmd_doze = "dumpsys deviceidle whitelist +%s" ascii
        $cmd_standby = "am set-standby-bucket %s active" ascii
        $cmd_disable = "pm disable-user --user 0 %s" ascii
        $cmd_uninstall = "pm uninstall -k --user 0 %s" ascii

        $loopback_port = "127.0.0.1:7910" ascii

    condition:
        ($_go_build or $_go_buildinfo)
        and $lib_name
        and $loopback_port
        and 3 of ($cmd_doze, $cmd_standby, $cmd_disable, $cmd_uninstall)
}