rule koktevrat_stage2_rat_uon_rc4 {
    meta:
        author = "Arnold Chan"
        description = "Detects Koktevrat Stage 2 Android RAT component (com.kowo.ciligeci) that unpacks the RC4-encrypted uoN.css/uoN.apk payload using the RC4 key iOZ"
        malware = "koktevrat"

    strings:
        $_dex = "dex\n035"
        $pkg = "com.kowo.ciligeci" ascii fullword
        $res1 = "uoN.css" ascii
        $res2 = "uoN.apk" ascii
        $key = "iOZ" ascii

    condition:
        ($_dex at 0 or uint32(0) == 0x04034b50) and
        $pkg and
        1 of ($res1, $res2) and
        $key
}