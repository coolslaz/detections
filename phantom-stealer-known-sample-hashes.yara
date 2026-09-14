import "hash"

rule phantom_stealer_known_sample_hashes {
    meta:
        author = "Arnold Chan"
        description = "Matches known Phantom Stealer MaaS infostealer sample hashes"
        malware = "Phantom Stealer"
    condition:
        hash.sha256(0, filesize) == "03ff10f626253ac8613b7c489170d602c524b9e8b69ebc13d677a800b0bdb0db" or
        hash.sha256(0, filesize) == "6a1e573c0068dc87d4f0fbe6782d0a253dd60b9f37b7f6c5c4d6c72547f16c05"
}