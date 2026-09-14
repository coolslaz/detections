import "hash"

rule silverfox_known_payload_hash_match {
    meta:
        author = "detections.ai"
        description = "Matches known SilverFox malware payload samples by SHA256 hash"

    condition:
        // Cheap filesize gate short-circuits before the SHA256 computation runs over the
        // full file -- skips hashing on files clearly outside a plausible payload size.
        filesize < 50MB and (
            hash.sha256(0, filesize) == "2ea2d574f6136c1dc4eac921c88a9d8588cadb0173099e89366538c908a5e959" or
            hash.sha256(0, filesize) == "a4c72fe2ed9e47535b57cb3f75f7cbdff6ae112cc4353882fb1fa9e7ea8cfa9c" or
            hash.sha256(0, filesize) == "4e60484018db6fd57c40a30525efd9224add1727440f3f0ec1d47c8918cb8642"
        )
}