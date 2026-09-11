import "hash"

rule redtail_known_file_hashes {
    meta:
        author = "Arnold Chan"
        description = "Matches known RedTail malware payloads and staging scripts by exact SHA-256 hash equality"
        malware = "RedTail"
        false_positive = "None, this rule relies on exact hash matching which produces no false positives assuming the hash database is accurate."
condition:
        hash.sha256(0, filesize) == "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e" or
        hash.sha256(0, filesize) == "efa731b59f9e2f277336072fe5c72b488793c842e2efeedf5cb571a0eeb224e2" or
        hash.sha256(0, filesize) == "31d4181843b1ed10a7e7cb3f108f6d6c50a7a4452ee52ddacabe8ca77260615e" or
        hash.sha256(0, filesize) == "197c74408e15bd1168105f564f96aace4fd4819961b724630bf5a6be4878daf8"
}