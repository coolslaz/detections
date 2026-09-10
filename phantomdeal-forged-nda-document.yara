rule phantomdeal_forged_nda_document {
    meta:
        author = "Arnold Chan"
        description = "Detects forged NDA documents used in Phantom Deal M&A fraud campaign, requiring co-occurrence of impersonated advisory firm branding, secrecy-clause language restricting communication to personal channels, and M&A-fraud-specific wire/payment indicators rather than secrecy-clause phrasing alone"
        actor = "Phantom Deal"
        false_positive1 = "Legitimate NDA templates that happen to reference the same consultancy firms and standard banking terminology in a legal context."
        false_positive2 = "Draft documents created by internal employees that might use personal email for temporary document sharing in non-malicious contexts."
        false_positive3 = "Marketing or research documents that discuss M&A trends and mention these advisory firms alongside common financial terminology."
strings:
        $nda_header = "NDA" ascii wide
        $confidential = "CONFIDENTIAL" ascii wide nocase

        $brand_pwc = "PwC" ascii wide
        $brand_kpmg = "KPMG" ascii wide
        $brand_ogier = "Ogier" ascii wide

        $chan_whatsapp = "WhatsApp" ascii wide nocase
        $chan_personal_email = "private e-mail" ascii wide nocase
        $chan_personal_email2 = "personal email" ascii wide nocase

        $wire_mt103 = "MT103" ascii wide nocase
        $wire_uetr = "UETR" ascii wide nocase
        $wire_swift = "SWIFT" ascii wide nocase
        $wire_beneficiary = "beneficiary bank" ascii wide nocase
        $wire_routing = "wire routing" ascii wide nocase
        $wire_proof = "proof of transfer" ascii wide nocase
        $wire_proof2 = "proof of wire transfer" ascii wide nocase

    condition:
        $nda_header and $confidential
        and any of ($brand_pwc, $brand_kpmg, $brand_ogier)
        and any of ($chan_whatsapp, $chan_personal_email, $chan_personal_email2)
        and 2 of ($wire_mt103, $wire_uetr, $wire_swift, $wire_beneficiary, $wire_routing, $wire_proof, $wire_proof2)
}