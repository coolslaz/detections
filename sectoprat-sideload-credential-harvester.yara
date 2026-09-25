import "pe"

rule sectoprat_sideload_credential_harvester {
    meta:
        author = "Arnold Chan"
        description = "Detects SectopRAT (Arechclient2) .NET RAT binaries deployed via tampered libcef.dll / JetBrains helper DLL sideloading that harvest browser credentials, cookies, credit card data, and files. Tightened to require combined sideload+family+target indicators plus .NET CLR import evidence, avoiding standalone generic strings."
        false_positive1 = "Security research tools or malware analysis labs that replicate malware behavior for testing purposes."
        false_positive2 = "Legitimate applications that share names with the JetBrains helper DLLs and are collocated with legitimate libcef.dll files."
strings:
        // DLL sideloading chain indicators (tampered libcef.dll + repurposed JetBrains helper) - require fullword to reduce noise from unrelated path substrings
        $sideload_1 = "libcef.dll" ascii nocase fullword
        $sideload_2 = "JetBrains" ascii nocase fullword

        // SectopRAT / Arechclient2 internal identifiers - these are the actual malware family markers, not generic
        $family_1 = "Arechclient2" ascii wide fullword
        $family_2 = "SectopRAT" ascii wide nocase fullword

        // Browser credential/cookie/data harvesting targets consistent with the attack chain - kept as fullword to avoid partial matches inside unrelated strings
        $target_1 = "Login Data" ascii wide fullword
        $target_2 = "\\Cookies" ascii wide nocase fullword
        $target_3 = "Credit Cards" ascii wide nocase fullword
        $target_4 = "Web Data" ascii wide fullword
        $target_5 = "Local State" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        // Require actual .NET CLR import evidence rather than a bare mscoree.dll string, since SectopRAT is a compiled .NET assembly
        pe.imports("mscoree.dll", "_CorExeMain") and
        // Require at least one explicit family marker string identifying SectopRAT/Arechclient2
        1 of ($family_*) and
        // Require the sideload chain evidence (tampered libcef.dll referencing a JetBrains helper) rather than either alone
        all of ($sideload_*) and
        // Raise threshold on generic harvesting target strings so isolated matches cannot trigger the rule
        3 of ($target_*) and
        // Loader DLLs sideloaded this way are typically small-to-mid sized .NET payloads, not massive binaries
        filesize < 15MB
}