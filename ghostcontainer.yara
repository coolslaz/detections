import "pe"

rule GhostContainer_Backdoor_NET_Assembly {
    meta:
        author = "Arnold Chan"
        description = "Detects GhostContainer .NET-based backdoor assembly components deployed on compromised Exchange servers, requiring multiple corroborating unique indicators (module/class names, C2 header, masquerading filenames) to reduce false positives on generic .NET assemblies"
        threat_name = "GhostContainer"
        reference = "Trojan.MSIL.GhostContainer.gen"
        false_positive1 = "Legitimate .NET assemblies that happen to share similar obfuscated module or class naming conventions."
        false_positive2 = "Third-party Exchange plugins or legitimate monitoring tools that might inadvertently use similar configuration filenames or class structures."
strings:
        $kaspersky_detect = "Trojan.MSIL.GhostContainer.gen" ascii wide
        $module_name = "App_Web_Container_1.dll" ascii wide nocase
        $class_name = "App_Web_8c9b251fb5b3" ascii wide
        $c2_header = "x-owa-urlpostdata" ascii wide nocase
        $masq1 = "AdobeSync.exe" ascii wide nocase
        $masq2 = "adobe_32.exe" ascii wide nocase
        $masq3 = "1c-office-plugin.exe" ascii wide nocase
        $masq4 = "1cbroker.exe" ascii wide nocase
        $masq5 = "trueconf-broker.exe" ascii wide nocase

    condition:
        pe.is_pe and
        (
            $kaspersky_detect
            or
            ($module_name and $class_name)
            or
            ($class_name and $c2_header)
            or
            ($module_name and $c2_header)
            or
            ((any of ($masq*)) and ($module_name or $class_name))
        )
}