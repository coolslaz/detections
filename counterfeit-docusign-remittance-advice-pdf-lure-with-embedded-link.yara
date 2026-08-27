rule counterfeit_docusign_remittance_advice_pdf_lure {
  meta:
    author = "detections.ai"
    description = "Detects PDF/document attachments styled as a genuine DocuSign remittance-advice share notice that embed a malicious hyperlink inside the document body rather than the email"
  strings:
    $_pdf_header = { 25 50 44 46 2D }
    $lure1 = "Accounting Department shared a PDF via DocuSign secure Remittance Advice.pdf" ascii wide nocase
    $lure2 = "Tap here to view document" ascii wide nocase
    $lure3 = "View with DocuSign" ascii wide nocase
    $lure4 = "Remittance Advice.pdf" ascii wide nocase
    $brand1 = "DocuSign" ascii wide nocase
    $brand2 = "docusign" ascii wide nocase
    $uri_action = "/URI" ascii
    $link_action = "/Link" ascii
    $annot = "/Annots" ascii
  condition:
    $_pdf_header at 0 and
    (any of ($lure1, $lure2, $lure3, $lure4)) and
    any of ($brand1, $brand2) and
    $annot and
    any of ($uri_action, $link_action)
}