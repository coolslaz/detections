import "hash"

rule koktevrat_known_apk_artifacts {
    meta:
        author = "Arnold Chan"
        description = "Detects known Koktevrat Android RAT campaign APK artifacts by published SHA-256 hashes and associated package name string"
        malware = "koktevrat"
        false_positive = "Legitimate applications that share the same package name or have hash collisions, though unlikely for these specific identifiers."
strings:
        $pkg = "com.kowo.ciligeci" ascii fullword

    condition:
        hash.sha256(0, filesize) == "f2042077e2d9fad0ad69e76e706311b3f690e0338ba4765491c4ed0257ad1189" or
        hash.sha256(0, filesize) == "568f1067735bb98185b9191998f798b6d59157673ca99446ce268f3ef6070154" or
        hash.sha256(0, filesize) == "6b7b09aa12a08951e822e6ab0e08bce4e4bf7b1ecd51bf9fe095cd06a7a445e3" or
        hash.sha256(0, filesize) == "7c24a56dcacc028648caafba5a209d0488db15412a2c22ac586db940710b5048" or
        (uint32(0) == 0x04034b50 and $pkg)
}