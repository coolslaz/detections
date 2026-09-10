import "pe"

rule qilin_ransomware_execution {
    meta:
        author = "Arnold Chan"
        description = "Detects potential Qilin ransomware binaries following Cisco FMC-based intrusion by UAT-11988. Source intel provides only name-level attribution (no sample hash/byte IOC for the payload), so this is tightened to a valid PE, a plausible ransomware-payload size band, and >=2 occurrences of the family string -- a bare single 'Qilin' substring in an arbitrary PE (e.g. an unrelated app, build path, or AV/report string) is not sufficient to alert on alone."
        threat_actor = "UAT-11988"
        false_positive = "A single incidental 'Qilin' string in an unrelated PE (product name, build path, AV/report text embedded in a binary) — mitigated by requiring a valid PE, a plausible ransomware-size band, and at least 2 occurrences of the family string."
strings:
        $family = "Qilin" ascii wide fullword nocase

    condition:
        pe.is_pe and
        filesize > 50KB and filesize < 15MB and
        #family >= 2
}