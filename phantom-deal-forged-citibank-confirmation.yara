rule phantom_deal_forged_citibank_confirmation {
    meta:
        author = "Arnold Chan"
        description = "Detects forged Citibank payment confirmation/account statement PDFs used in Phantom Deal BPC fraud to falsely demonstrate wire transfer progress; requires combination of bank branding with fraud-specific SWIFT/routing/CTA artifacts"
        actor = "Phantom Deal"
        false_positive1 = "Legitimate email correspondence from Citibank containing actual payment confirmation documents"
        false_positive2 = "Marketing materials or educational PDFs from financial institutions that happen to use similar terminology"
        false_positive3 = "Internal financial reporting documents that use standardized SWIFT/BIC nomenclature"
strings:
        $_pdf_header = { 25 50 44 46 2D }

        $bank1 = "Citibank Europe" ascii wide nocase
        $bank2 = "Citigroup Centre" ascii wide nocase
        $bank3 = "citigroup.com/citi/contact.html" ascii wide nocase

        $swift1 = "MT103" ascii wide nocase
        $swift2 = "SWIFT/BIC" ascii wide nocase
        $swift3 = "BIC code" ascii wide nocase

        $ref1 = "Wire routing" ascii wide nocase
        $ref2 = "routing number" ascii wide nocase

        $cta1 = "View Transaction Details" ascii wide nocase
        $cta2 = "Dear Valued Customer" ascii wide nocase

    condition:
        $_pdf_header at 0
        and 1 of ($bank*)
        and 1 of ($swift*)
        and 1 of ($ref*)
        and 1 of ($cta*)
        and 5 of ($bank*,$swift*,$ref*,$cta*)
}