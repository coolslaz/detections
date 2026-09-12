rule operation_doppelbrand_spoofed_servicenow_invoice {
    meta:
        author = "Arnold Chan"
        description = "Detects spoofed ServiceNow invoice attachments/HTML used in Operation DoppelBrand BEC campaign with attacker-controlled GO2BANK ACH details"
        malware = "Brickstorm"
        campaign = "Operation DoppelBrand"
        false_positive = "Genuine ServiceNow subscription/renewal invoices that mention 'ServiceNow, Inc.', 'ServiceNow Platform', or 'due bill' without any of the campaign's unique fraud indicators"
strings:
        $bank = "GO2BANK" ascii wide nocase
        $fraud_email = "gomez@service-nowinc.com" ascii wide nocase
        $lookalike_domain = "service-nowinc.com" ascii wide nocase
        $amount1 = "49,465.90" ascii wide
        $amount2 = "49465.90" ascii wide
        $ach_type = "ACH Only" ascii wide
        $misspell = "ACH Parment" ascii wide nocase
        $subj_due = "due bill" ascii wide nocase
        $vendor_brand = "ServiceNow, Inc." ascii wide
        $subscription = "ServiceNow Platform" ascii wide nocase

    condition:
        ($fraud_email or $lookalike_domain or $misspell or $amount1 or $amount2) and 2 of ($bank, $fraud_email, $lookalike_domain, $amount1, $amount2, $ach_type, $misspell, $subj_due, $vendor_brand, $subscription)
}