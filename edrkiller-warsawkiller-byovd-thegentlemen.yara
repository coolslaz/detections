rule edrkiller_warsawkiller_byovd_thegentlemen {
    meta:
        author = "Arnold Chan"
        description = "Detects EDRKiller.exe or WarsawKiller.exe binaries and the associated wsftprm.sys BYOVD driver used by The Gentlemen threat actor to terminate security product processes"
        false_positive = "Extremely unlikely: would require a legitimate PE binary under 5MB that both references two of the tool-specific strings/driver filename AND imports a service-control or device-IO API used for driver installation."
strings:
        $name1 = "EDRKiller.exe" ascii wide nocase
        $name2 = "WarsawKiller.exe" ascii wide nocase
        $src1 = "EDRKiller.c" ascii wide nocase
        $src2 = "WarsawKiller.c" ascii wide nocase
        $driver = "wsftprm.sys" ascii wide nocase
        $api1 = "OpenSCManagerW" ascii
        $api2 = "CreateServiceW" ascii
        $api3 = "DeviceIoControl" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 5MB
        and (2 of ($name1, $name2, $src1, $src2, $driver))
        and (1 of ($api1, $api2, $api3))
}