rule Beamglea_ClickFix_Fake_Captcha_HTML_DDR
{
    meta:
        author = "detections.ai"
        description = "Detects HTML pages embedding fake Cloudflare CAPTCHA verification content combined with obfuscated JavaScript that fetches and decodes a remote redirect URL (Beamglea/ClickFix DDR pattern)"
        threat_actor = "Beamglea"
        malware = "ClickFix, Beamglea"

    strings:
        $captcha1 = "Verify you are human" ascii wide nocase
        $captcha2 = "I am human" ascii wide nocase
        $cloudflare = "CLOUDFLARE" ascii wide nocase
        $rayid = "Ray ID" ascii wide nocase

        $ddr1 = "api.keyval.org" ascii wide nocase
        $ddr2 = "login.microsofte.live" ascii wide nocase
        $ddr3 = "unpkg.com" ascii wide nocase

        $redirect1 = "window.location" ascii
        $redirect2 = "window.location.href" ascii

        $fetch1 = "fetch(" ascii
        $fetch2 = "XMLHttpRequest" ascii

        $htmltag = "<html" ascii nocase

    condition:
        $htmltag and
        1 of ($captcha1, $captcha2, $rayid) and
        1 of ($ddr1, $ddr2, $ddr3) and
        1 of ($redirect1, $redirect2) and
        1 of ($fetch1, $fetch2)
}