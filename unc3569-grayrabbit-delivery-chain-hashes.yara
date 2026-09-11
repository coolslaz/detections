import "hash"
import "pe"

rule unc3569_grayrabbit_delivery_chain_hashes {
    meta:
        author = "Arnold Chan"
        description = "Detects known malicious file hashes for GRAYRABBIT delivery chain components: trojanized 7zp.dll loader, encrypted PE loader shellcode, and GRAYRABBIT backdoor core.dll, gated on PE structural validity and filesize"
        mitre_attack = "T1574.002, T1620"
        threat_actor = "UNC3569"
        malware = "GRAYRABBIT"
        false_positive = "Legitimate security software or forensic tools performing signature-based scanning could trigger these alerts if they share hash values, although highly unlikely for malicious file hashes."
strings:
        $_mz_header = { 4D 5A }

    condition:
        ($_mz_header at 0 or pe.is_pe) and
        filesize > 1KB and filesize < 10MB and
        (
            hash.sha256(0, filesize) == "29c7ee41d0cc9e07d981e451df56d0c3d37c41ac4ec10c7b516cc033ee397a63" or
            hash.sha256(0, filesize) == "749160a2f20f82744026719cf72e483595c6aad718efa74d675a98662e02422e" or
            hash.sha256(0, filesize) == "d7a3c7eb94edc0e020f74c678743d71d61e944634aade4a67a96c3589e828b3a"
        )
}