import "pe"

rule ghostcontainer_masquerading_executable_filenames {
    meta:
        author = "Arnold Chan"
        description = "Detects PE executables whose embedded filename strings claim to be Adobe, TrueConf, or 1C software but whose PE metadata (company/product name) or digital signature does not match the claimed vendor, as used by NightEagle/GhostContainer operators to blend malicious tooling into normal process activity"
        false_positive1 = "Legitimate software renamed by users or system administrators for custom deployment scripts."
        false_positive2 = "Custom, internal, or open-source software that shares filenames with major vendor products but lacks enterprise digital signature certificates."
        false_positive3 = "Unsigned or self-signed enterprise-internal binaries that may use common naming conventions."
strings:
        $fn1 = "adobe_32.exe" ascii wide nocase
        $fn2 = "AdobeSync.exe" ascii wide nocase
        $fn3 = "trueconf.exe" ascii wide nocase
        $fn4 = "trueconf-broker.exe" ascii wide nocase
        $fn5 = "1cbroker.exe" ascii wide nocase
        $fn6 = "1c-office-plugin.exe" ascii wide nocase

    condition:
        pe.is_pe and
        (
            (
                any of ($fn1, $fn2) and
                not (
                    for any i in (0..pe.number_of_signatures - 1) : (
                        pe.signatures[i].subject icontains "Adobe"
                    )
                    or
                    pe.version_info["CompanyName"] icontains "Adobe"
                )
            )
            or
            (
                any of ($fn3, $fn4) and
                not (
                    for any i in (0..pe.number_of_signatures - 1) : (
                        pe.signatures[i].subject icontains "TrueConf"
                    )
                    or
                    pe.version_info["CompanyName"] icontains "TrueConf"
                )
            )
            or
            (
                any of ($fn5, $fn6) and
                not (
                    for any i in (0..pe.number_of_signatures - 1) : (
                        pe.signatures[i].subject icontains "1C"
                    )
                    or
                    pe.version_info["CompanyName"] icontains "1C"
                )
            )
        )
}