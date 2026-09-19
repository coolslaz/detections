rule ottercookie_js_rat_artifacts {
    meta:
        author = "Arnold Chan"
        description = "Detects OtterCookie JavaScript-based RAT/infostealer malware artifacts associated with WaterPlum/Contagious Interview campaign"
        malware = "OtterCookie"
        actor = "WaterPlum"
        false_positive1 = "Legitimate security assessment or penetration testing tools that utilize clipboard monitoring or screenshot functionality for auditing purposes."
        false_positive2 = "Legitimate remote administration or screen-sharing software, though these are typically digitally signed by reputable vendors."
strings:
        $name = "OtterCookie" ascii wide nocase
        $s1 = "ottercookie" ascii nocase
        $s2 = "getClipboardData" ascii
        $s3 = "clipboardy" ascii
        $s4 = "screenshot-desktop" ascii

    condition:
        filesize < 5MB and
        ( $name or ( $s1 and 2 of ($s2, $s3, $s4) ) )
}