rule ottercandy_hybrid_rat_artifacts {
    meta:
        author = "Arnold Chan"
        description = "Detects file artifacts referencing OtterCandy malware, which combines OtterCookie and RATatouille RAT capabilities, associated with WaterPlum/Contagious Interview campaign"
        actor = "WaterPlum"
        campaign = "Contagious Interview"
        reference = "https://attack.mitre.org/groups/G1052/"
        false_positive = "Security research tools, malware analysis sandboxes, or incident response scripts that contain samples or documentation related to OtterCandy, OtterCookie, or RATatouille."
strings:
        $name1 = "OtterCandy" ascii wide nocase
        $name2 = "RATatouille" ascii wide nocase
        $name3 = "OtterCookie" ascii wide nocase

    condition:
        filesize < 20MB and 2 of them
}