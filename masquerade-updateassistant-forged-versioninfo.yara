import "pe"

rule masquerade_updateassistant_forged_versioninfo {
    meta:
        author = "Arnold Chan"
        description = "Detects PE binaries masquerading as Microsoft's Windows Update Assistant via forged VersionInfo metadata combined with an unsigned or invalid/unverified digital signature, associated with HVNC backdoor delivery"
        reference = "T1036.005"
        false_positives = "Legitimate Microsoft-signed update binaries with valid, verified Authenticode signatures are excluded; false positives limited to third-party tools that both forge Microsoft VersionInfo fields and ship unsigned or with an invalid signature"
strings:
        $filename = "UpdateAssistant.exe" ascii wide nocase
        $product_name = "Windows Update Assistant" ascii wide
        $company_name = "Microsoft Corporation" ascii wide
        $_mz = { 4D 5A }

    condition:
        $_mz at 0 and
        pe.is_pe and
        $filename and
        $product_name and
        $company_name and
        (
            pe.number_of_signatures == 0
            or not pe.signatures[0].verified
        )
}