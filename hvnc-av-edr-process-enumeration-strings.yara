rule hvnc_av_edr_process_enumeration_strings {
    meta:
        author = "Arnold Chan"
        description = "Detects HVNC backdoor payload containing hardcoded AV/EDR process names combined with process enumeration APIs and a hex-suffixed mutex naming pattern, reducing false positives from generic AV name or API string matches alone"
        threat_actor = "Silver Fox"
        false_positives = "Very low. Requires simultaneous presence of at least 4 distinct hardcoded AV/EDR process name strings, all three Toolhelp32 process-enumeration API imports, AND a mutex name matching the specific hex-suffixed Global\\AppUpdateHelper_/Global\\WinSvc_ pattern observed in this HVNC payload family within a PE file. Legitimate software enumerating processes for AV compatibility checks would not also contain this exact mutex naming convention."
strings:
        $_mz = { 4D 5A }

        $av1 = "avastui.exe" ascii wide nocase
        $av2 = "bdagent.exe" ascii wide nocase
        $av3 = "mcshield.exe" ascii wide nocase
        $av4 = "360tray.exe" ascii wide nocase
        $av5 = "ekrn.exe" ascii wide nocase

        $api1 = "CreateToolhelp32Snapshot" ascii
        $api2 = "Process32First" ascii
        $api3 = "Process32Next" ascii

        $mutex1 = /Global\\AppUpdateHelper_[0-9A-F]{4,10}/ ascii wide
        $mutex2 = /Global\\WinSvc_[0-9A-F]{4,10}/ ascii wide

    condition:
        $_mz at 0 and
        4 of ($av*) and
        all of ($api*) and
        1 of ($mutex*)
}