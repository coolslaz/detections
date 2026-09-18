import "hash"

rule clickfix_stealc_knownhash_dropper_payload {
    meta:
        author = "Arnold Chan"
        description = "Detects known PowerShell dropper and embedded StealC payload binaries used in the ClickFix infection chain via exact SHA256 hash equality only"
    condition:
        hash.sha256(0, filesize) == "1e4246ed2050b7a6c711aae4732e8ec89d590dec860d16ecc86071339792135f" or
        hash.sha256(0, filesize) == "41da18c32a2c759946acd9e2291e937b0777e19db6407126807f9af52374e3c0"
}