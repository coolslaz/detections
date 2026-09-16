import "pe"

rule ghostcontainer_net_backdoor_assembly {
    meta:
        author = "Arnold Chan"
        description = "Detects the GhostContainer .NET-based backdoor assembly deployed on compromised Microsoft Exchange servers, requiring multiple corroborating unique indicators (C2 header, proxy class name, virtual path parameters) alongside .NET/PE structure to reduce false positives"
        malware = "GhostContainer"
        reference = "Trojan.MSIL.GhostContainer.gen"
        false_positive1 = "Legitimate .NET assemblies associated with custom Exchange extensions that happen to share internal naming conventions or headers"
        false_positive2 = "Security testing or research tools that intentionally emulate web shell headers and paths for validation"
strings:
        $c2_header = "x-owa-urlpostdata" ascii wide nocase
        $proxy_class = "App_Web_8c9b251fb5b3" ascii wide
        $vpath1 = "fakePath" ascii wide
        $vpath2 = "fakePageName" ascii wide

        $_net_header = "mscorlib" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        $_net_header and
        (
            ($proxy_class and $c2_header) or
            ($proxy_class and $vpath1 and $vpath2) or
            ($c2_header and $vpath1 and $vpath2)
        )
}