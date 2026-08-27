rule DOUBLOON_DREDGER_Notion_PDF_Overlapping_Links {
    meta:
        author = "detections.ai"
        description = "Detects PDF lures abused by DOUBLOON DREDGER that impersonate Notion share/invite notifications and embed 2-3 overlapping redundant hyperlinks leading to EvilTokens device code harvesting pages"
        actor = "DOUBLOON DREDGER"
        malware = "EvilTokens"

    strings:
        $_pdf_magic = "%PDF-"

        $notion1 = "Notion" ascii wide nocase
        $notion2 = "shared a document with you" ascii wide nocase
        $notion3 = "invited you to" ascii wide nocase
        $notion4 = "View in Notion" ascii wide nocase

        $uri1 = "/URI" ascii
        $uri2 = "/Subtype/Link" ascii
        $uri3 = "/Subtype /Link" ascii

    condition:
        $_pdf_magic at 0
        and 1 of ($notion*)
        and #uri1 >= 2
        and (#uri2 >= 2 or #uri3 >= 2)
}