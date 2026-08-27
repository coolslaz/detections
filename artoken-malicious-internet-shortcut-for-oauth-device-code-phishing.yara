rule ARToken_Malicious_URL_DeviceCode_Phishing {
    meta:
        author = "detections.ai"
        description = "Detects Windows Internet Shortcut (.url) files used by ARToken to lure victims into OAuth device code phishing via a fake identity-verification prompt, delivered from anonymous SharePoint shares"
    strings:
        $_header = "[InternetShortcut]" ascii

        $url_field = /URL\s*=\s*https?:\/\// ascii nocase
        $devicecode1 = "devicelogin" ascii nocase
        $devicecode2 = "oauth2/deviceauth" ascii nocase
        $devicecode3 = "microsoft.com/devicelogin" ascii nocase

        $lure1 = "identity verification" ascii nocase
        $lure2 = "verify your identity" ascii nocase
        $lure3 = "invoice" ascii nocase

    condition:
        $_header at 0
        and $url_field
        and any of ($devicecode*)
        and any of ($lure*)
}