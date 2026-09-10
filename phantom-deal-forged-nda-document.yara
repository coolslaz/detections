rule phantom_deal_forged_nda_document {
    meta:
        author = "Arnold Chan"
        description = "Detects forged NDA documents used in Phantom Deal fake acquisition fraud, requiring corroborating secrecy-clause language and M&A-fraud-specific wire-transfer/payment phrasing alongside impersonated advisory brands"
        campaign = "Phantom Deal"
        false_positive1 = "Legitimate NDA templates used by authorized personnel that happen to reference the same advisory firms."
        false_positive2 = "Internal training documents referencing standard M&A fraud indicators."
        false_positive3 = "Research reports or news articles discussing the Phantom Deal or similar business acquisition fraud tactics."
strings:
        $title1 = "NDA CONFIDENTIAL" nocase ascii wide

        $brand1 = "PwC" ascii wide
        $brand2 = "KPMG" ascii wide
        $brand3 = "Ogier" ascii wide

        $secrecy1 = "not be disclosed to Legal, Finance, Treasury, Compliance" nocase ascii wide
        $secrecy2 = "Legal, Finance, Treasury, Compliance" nocase ascii wide
        $secrecy3 = "Corporate Development" nocase ascii wide

        $channel1 = "WhatsApp" ascii wide
        $channel2 = "private e-mail" nocase ascii wide
        $channel3 = "personal email" nocase ascii wide
        $channel4 = "sole communication channel" nocase ascii wide

        $fraud1 = "MT103" ascii wide
        $fraud2 = "UETR" ascii wide
        $fraud3 = "proof of transfer" nocase ascii wide
        $fraud4 = "official proof of wire transfer" nocase ascii wide
        $fraud5 = "confidential acquisition" nocase ascii wide

        $ann1 = "public announcement" nocase ascii wide

        $_pdf_header = { 25 50 44 46 2D }

    condition:
        $_pdf_header at 0
        and $title1
        and any of ($brand1, $brand2, $brand3)
        and any of ($secrecy1, $secrecy2, $secrecy3)
        and any of ($channel1, $channel2, $channel3, $channel4)
        and any of ($fraud1, $fraud2, $fraud3, $fraud4, $fraud5)
        and 6 of ($title1, $brand1, $brand2, $brand3, $secrecy1, $secrecy2, $secrecy3, $channel1, $channel2, $channel3, $channel4, $fraud1, $fraud2, $fraud3, $fraud4, $fraud5, $ann1)
}