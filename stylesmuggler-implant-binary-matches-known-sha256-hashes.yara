import "hash"

rule StyleSmuggler_Implant_Known_SHA256_Hashes {
    meta:
        author = "detections.ai"
        description = "Detects StyleSmuggler implant binaries (gvfsd-user / kworker-disguised Rust implant) by matching published SHA256 hashes"
    condition:
        hash.sha256(0, filesize) == "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7" or
        hash.sha256(0, filesize) == "b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420" or
        hash.sha256(0, filesize) == "8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef" or
        hash.sha256(0, filesize) == "251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220"
}