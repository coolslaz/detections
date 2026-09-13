rule papercut_mimikatz_credential_harvesting_papercut_campaign_ {
    meta:
        author = "Arnold Chan"
        description = "Detects Mimikatz binary or in-memory module used for credential harvesting following PaperCut RCE exploitation"
        reference = "CVE-2026-81578, CVE-2026-82078"
        false_positive1 = "Security audit software and penetration testing tools that utilize Mimikatz modules for authorized assessment."
        false_positive2 = "Legitimate administrative software that may share similar string patterns or module names if not properly constrained."
strings:
        $mimikatz_name1 = "mimikatz.exe" ascii wide nocase
        $mimikatz_name2 = "mimikatz" ascii wide nocase fullword
        $cmd1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd2 = "sekurlsa::" ascii wide nocase
        $banner1 = "gentilkiwi" ascii wide nocase
        $banner2 = "Benjamin DELPY" ascii wide nocase
        $module1 = "privilege::debug" ascii wide nocase
        $module2 = "lsadump::" ascii wide nocase

    condition:
        (uint16(0) == 0x5A4D and filesize < 5MB) and
        (
            $mimikatz_name1 or
            2 of ($mimikatz_name2, $cmd1, $cmd2, $banner1, $banner2, $module1, $module2)
        )
}