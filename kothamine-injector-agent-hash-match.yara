import "hash"

rule kothamine_injector_agent_hash_match {
  meta:
    author = "Arnold Chan"
    description = "Matches published SHA-256 hashes for the Kothamine Injector and Agent DLL, which drop MicrosoftEdgeUpdateCore.exe/.dll and inject into explorer.exe. Exact full-file SHA-256 match only, no fuzzy or partial matching, no additional PE structural checks."
  condition:
    hash.sha256(0, filesize) == "ec4219a7ecf132c29080fbb20e4ab410c57faa85aeed7acade1eb15d905a6ee0" or
    hash.sha256(0, filesize) == "74eca3973ad72a6ddc9397aff8250d9ee287211fc9a055d5ee290d01cf76a70c"
}