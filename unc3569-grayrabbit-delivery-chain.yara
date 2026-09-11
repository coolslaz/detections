import "pe"

rule unc3569_grayrabbit_delivery_chain {
    meta:
        author      = "Arnold Chan"
        description = "Detects trojanized 7z.dll loader and encrypted GRAYRABBIT payload components dropped during the UNC3569 exploit chain"
        date        = "2026-09-11"
        threat_actor = "UNC3569"
        malware     = "GRAYRABBIT"
        false_positive1 = "Legitimate use of the 7-Zip library or utilities that may coincidentally contain strings matching the detection logic."
        false_positive2 = "System administration or backup tools that perform reflective loading or use similar file staging paths in Public Documents."
strings:
        // SHA256: 29c7ee41d0cc9e07d981e451df56d0c3d37c41ac4ec10c7b516cc033ee397a63 - trojanized 7zp.dll/boy.dll
        // SHA256: 749160a2f20f82744026719cf72e483595c6aad718efa74d675a98662e02422e - encrypted PE loader shellcode (p)
        // SHA256: d7a3c7eb94edc0e020f74c678743d71d61e944634aade4a67a96c3589e828b3a - core.dll GRAYRABBIT backdoor

        // structural gate only, not counted as malicious indicators
        $_mz = { 4D 5A }

        // CoreClientInstall reflective loader export present in GRAYRABBIT / trojanized DLL
        $export_core = "CoreClientInstall" ascii fullword

        // Reflective PE loading function names unique to this loader
        $fn_parse    = "PE_ParseHeaders" ascii fullword
        $fn_resolve  = "PE_ResolveAPIByHash" ascii fullword
        $fn_map      = "PE_ReflectiveMap" ascii fullword
        $fn_export   = "PE_ResolveExportByHash" ascii fullword

        // GRAYRABBIT C2 RC4 key (6-byte static key used for every 0x1000-byte frame)
        $rc4_key     = "m5b1u3" ascii

        // GRAYRABBIT C2 domain fragment split across XMM constant (plain half)
        $c2_domain   = "uaiubifas" ascii

        // C2 protocol message-type tags parsed by the RC4-decrypted frame handler
        $c2_msg_tag  = "msg\xFF" ascii
        $c2_file_tag = "file" ascii fullword

        // Staging server path artefact written by shellcode downloader
        $staging_path = "C:\\Users\\Public\\Documents\\7z.exe" ascii wide
        $payload_path = "C:\\Users\\Public\\Documents\\p.7z" ascii wide

        // Anti-sandbox process-count gate threshold (0x32 = 50 decimal) immediately preceding CreateToolhelp32Snapshot-style compare
        $proc_snap   = { 68 32 00 00 00 }   // push 0x32 (process threshold constant)

    condition:
        pe.is_pe and
        $_mz at 0 and
        filesize > 20KB and filesize < 5MB and
        (
            // Match trojanized loader DLL by its unique reflective-load exports
            ( $export_core and all of ($fn_parse, $fn_resolve, $fn_map, $fn_export) ) or
            // Match GRAYRABBIT backdoor by C2 RC4 key, domain fragment, and protocol tags
            ( $rc4_key and $c2_domain and 1 of ($c2_msg_tag, $c2_file_tag) ) or
            // Match loader by staging paths written to disk together with anti-sandbox gate
            ( $staging_path and $payload_path and $proc_snap ) or
            // Fallback: require a strong majority of distinctive payload strings
            ( 4 of ($export_core, $fn_parse, $fn_resolve, $fn_map, $fn_export, $rc4_key, $c2_domain, $c2_msg_tag, $c2_file_tag, $staging_path, $payload_path, $proc_snap) )
        )
}