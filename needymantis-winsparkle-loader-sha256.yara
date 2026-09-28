import "hash"

rule needymantis_winsparkle_loader_sha256 {
  meta:
    author = "Arnold Chan"
    description = "Exact-hash match for the known NeedyMantis first-stage loader sample masquerading as Poedit's WinSparkle.dll"
    malware_family = "NeedyMantis"
    hash = "e842dd7642c8e04b5ec20b6393848a9c904e4832930950c16664fe7800ba382e"
    reference = "https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/"
    false_positive1 = "None expected: SHA-256 exact-match hashing has cryptographically negligible collision probability, so a hit is byte-identical to a confirmed-malicious sample"
    false_positive2 = "A hit only proves the exact known sample is present, not that a look-alike or recompiled variant of the malware is present -- new builds will need new hashes"
condition:
    filesize > 0 and hash.sha256(0, filesize) == "e842dd7642c8e04b5ec20b6393848a9c904e4832930950c16664fe7800ba382e"
}

rule NeedyMantis_WinSparkle_Archive_SHA256 {
  meta:
    author = "Arnold Chan"
    description = "Exact-hash match for the known NeedyMantis encrypted WinSparkle archive paired with the first-stage loader"
    malware_family = "NeedyMantis"
    hash = "9cb68f986043a576e19d32184c583b7d8f571c7219d8dc0065dced1c13f077ef"
    reference = "https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/"
  condition:
    filesize > 0 and hash.sha256(0, filesize) == "9cb68f986043a576e19d32184c583b7d8f571c7219d8dc0065dced1c13f077ef"
}

rule NeedyMantis_libcurl_Archive_SHA256 {
  meta:
    author = "Arnold Chan"
    description = "Exact-hash match for the older known NeedyMantis encrypted libcurl archive variant"
    malware_family = "NeedyMantis"
    hash = "c82520eb03c084226be4eafbff46f56dca0aa8804a2a7f23a085a96afe71ef77"
    reference = "https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/"
  condition:
    filesize > 0 and hash.sha256(0, filesize) == "c82520eb03c084226be4eafbff46f56dca0aa8804a2a7f23a085a96afe71ef77"
}