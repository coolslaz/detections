rule trojan_hvnc_updateassistant_masquerade {
    meta:
        author = "Arnold Chan"
        description = "Detects HVNC final payload masquerading as Windows Update Assistant, combining Firefox credential theft strings, hardcoded AV process names, and XOR-encoded C2 host configuration"
        hash = "5fbfc7929858c3c3d79637db857525695db3c0f41b9bf2a7b964c26b7226bde3"
        false_positives = "Requires simultaneous presence of Firefox profile-theft strings, at least two hardcoded AV/EDR process names, and the XOR-encoded C2 host byte pattern within an MZ file; standalone matches on any single indicator category (e.g. legitimate update tooling referencing AV process names, or unrelated software touching Firefox sqlite files) will not trigger this rule."
strings:
        $_mz = { 4D 5A }

        // Firefox data theft targets
        $ff1 = "cookies.sqlite" ascii wide nocase
        $ff2 = "places.sqlite" ascii wide nocase
        $ff3 = "permissions.sqlite" ascii wide nocase

        // Masquerading version metadata
        $ver1 = "Windows Update Assistant" ascii wide
        $ver2 = "UpdateAssistant.exe" ascii nocase

        // HVNC C2 handshake / version markers
        $c2_1 = "CLIENT_ID:HVNC-" ascii
        $c2_2 = "IDENTIFIER_CHANNEL:" ascii
        $c2_3 = "VERSION:1.2.0.4.71" ascii

        // Hardcoded AV/EDR process enumeration
        $av1 = "avastui.exe" ascii nocase
        $av2 = "bdagent.exe" ascii nocase
        $av3 = "mcshield.exe" ascii nocase
        $av4 = "360tray.exe" ascii nocase
        $av5 = "ekrn.exe" ascii nocase

        // XOR-encoded C2 host byte pattern (key 0x37 decodes to 5.230.249.49) with service port string
        $xorhost = { 02 19 05 04 07 19 05 03 0E 19 03 0E }
        $port = "27015" ascii

    condition:
        $_mz at 0
        and any of ($ff*)
        and 2 of ($av*)
        and $xorhost
        and (any of ($ver*) or any of ($c2_*) or $port)
}