rule Beamglea_Fake_Cloudflare_CAPTCHA_HTML_Lure {
    meta:
        author = "detections.ai"
        description = "Detects fake Cloudflare 'Verify you are human' CAPTCHA HTML lure pages used by the Beamglea/ClickFix campaign, typically hosted as single-file npm packages mirrored via unpkg.com"
        threat_actor = "Beamglea"
        malware = "ClickFix, Beamglea"

    strings:
        $_html_tag = "<html" nocase

        $cf_brand1 = "CLOUDFLARE" nocase
        $cf_brand2 = "Verify you are human" nocase
        $cf_checkbox = "I am human" nocase
        $cf_rayid = "Ray ID" nocase
        $cf_privacy = "Privacy" nocase

        $api_keyval = "api.keyval" nocase
        $typosquat = "microsofte" nocase

        $js_fetch = "fetch(" nocase
        $js_decode1 = "atob(" nocase
        $js_decrypt = "decrypt" nocase
        $js_redirect = "window.location" nocase

    condition:
        $_html_tag and
        2 of ($cf_brand1, $cf_brand2, $cf_checkbox, $cf_rayid, $cf_privacy) and
        2 of ($js_fetch, $js_decode1, $js_decrypt, $js_redirect) and
        1 of ($api_keyval, $typosquat)
}