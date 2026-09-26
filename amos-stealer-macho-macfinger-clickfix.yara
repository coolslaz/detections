import "hash"

rule amos_stealer_macho_macfinger_clickfix {
    meta:
        author = "Arnold Chan"
        description = "Detects architecture-specific Mach-O 64-bit AMOS Stealer binaries dropped by the Macfinger ClickFix first-stage shell script, requiring multiple distinctive C2 endpoint strings alongside Mach-O magic and size constraints to reduce false positives"
        false_positive1 = "Legitimate macOS applications that happen to use similar API endpoints or network diagnostic tools that query ipinfo.io."
        false_positive2 = "Development or internal tooling within the 30MB-40MB size range that coincidentally includes similar string fragments."
strings:
        $_macho_64_le = { CF FA ED FE }
        $_macho_64_be = { FE ED FA CF }

        $ep_shell_agent = "/api/shell/agent" ascii
        $ep_credentials = "/api/credentials" ascii
        $ep_collect = "/api/t" ascii
        $ip_lookup = "ipinfo.io" ascii

    condition:
        (
            ($_macho_64_le at 0 or $_macho_64_be at 0)
            and filesize > 30MB and filesize < 40MB
            and 3 of ($ep_shell_agent, $ep_credentials, $ep_collect, $ip_lookup)
        )
        or hash.sha256(0, filesize) == "b68cdb1b46502fbce67ce3f8110682936d06afd2116af096e30abd4c8376b6dc"
        or hash.sha256(0, filesize) == "1a3765e8cb0055ec31693b8f82ce9744106dee08368259661600b072c6805af4"
}