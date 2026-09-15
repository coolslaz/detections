rule needlestealer_go_payload_diegovalanire {
    meta:
        author = "Arnold Chan"
        description = "Detects NeedleStealer Go-based stealer payload via embedded module path, internal API namespace, build tag, and C2 backend domain"
        threat_actor = "DPRK"
        malware = "NeedleStealer"
        campaign = "GAPI_Update"
        hash = "487f15344db40bca9c8cd853d76cd3e56f15422c9db73e4bc2c2b6c0bcea2806"
        reference = "https://haveibeensquatted.com/blog/from-fake-interview-to-signed-clickonce-three-payload-windows-chain"
        false_positive = "Legitimate software built with Go that happens to use similar internal project naming structures or module paths if they overlap with the specified strings."
strings:
        $mod_path = "needle-app" ascii wide
        $api_ns = "needle-app/internal/api" ascii wide
        $build_tag = "fe9dd150d4389cc4" ascii wide
        $c2_domain = "diegovalanire.digital" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        ($mod_path or $api_ns) and
        ($build_tag or $c2_domain)
}