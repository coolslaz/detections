import "hash"

rule ToyGhouls_BirdAgent_Backdoor_Binaries {
    meta:
        author = "detections.ai"
        description = "Detects known Toy Ghouls backdoor binaries cplsupport.exe and wtass.exe by MD5 hash"
    strings:
        $_fn1 = "cplsupport.exe" ascii wide nocase
        $_fn2 = "wtass.exe" ascii wide nocase
        $_cfg = "config.toml" ascii wide nocase
    condition:
        hash.md5(0, filesize) == "bfadbeee63a4f0bf19ec9deb8fa58f58" or
        hash.md5(0, filesize) == "7916c33688385525078bee504c90f359" or
        ($_fn1 or $_fn2) and $_cfg
}