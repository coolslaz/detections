import "hash"

rule vidar_known_sample_hashes_v2_0_to_v3_4 {
    meta:
        author = "Arnold Chan"
        description = "Matches known Vidar Stealer sample SHA256 hashes spanning versions 2.0 through 3.4 as identified by Zscaler ThreatLabz"
        malware = "Vidar"
        false_positive = "None, as this rule relies on specific static file hashes of known malicious samples."
condition:
        hash.sha256(0, filesize) == "1628bb03db87f67661349e169d73ee14ed490bdbf22abfbda08ccc9ebe237974" or
        hash.sha256(0, filesize) == "625a381981fc2d4c25c981d98b1d66bb2cf5da2dde2f590add0673a857d5b074" or
        hash.sha256(0, filesize) == "2d43d592630ad1e012da63ef7279f95dd4a8e94964e12ca2f996051875574fa6" or
        hash.sha256(0, filesize) == "979048a749d8f28d877c7068b1b336ecd1e349869dfb1d7c68118f90e4099bc4"
}