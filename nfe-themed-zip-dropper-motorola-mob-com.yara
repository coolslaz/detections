import "hash"

rule nfe_themed_zip_dropper_motorola_mob_com {
    meta:
        author = "Arnold Chan"
        description = "Detects the malicious NFe-themed ZIP dropper MOTOROLA_MOB_COM_NFe_2026-07-16_21781624.zip by known hash and archive structure"
        sha1 = "AB996D8A995F9152D7F6ADDC5C6248321E2952"
        sha256 = "97F35BA586FC121590C867B4D06787777FBECA2CE5AD07787EC896548B47CD"
        false_positives = "None expected; rule requires an exact SHA256 hash match to the known-malicious sample in addition to ZIP magic bytes, eliminating filename-only false positives"
strings:
        $_zip_magic = { 50 4B 03 04 }
        $_filename = "MOTOROLA_MOB_COM_NFe_2026-07-16_21781624" ascii wide nocase

    condition:
        $_zip_magic at 0 and
        hash.sha256(0, filesize) == "97f35ba586fc121590c867b4d06787777fbeca2ce5ad07787ec896548b47cd"
}