rule polinrider_appended_config_payload {
    meta:
        author = "Arnold Chan"
        description = "Detects the PolinRider/GHAPPIER campaign signature of a malicious loader payload silently appended to the end of a legitimate project configuration file"
        campaign = "PolinRider"
        malware = "GHAPPIER"
        false_positive1 = "Legitimate build scripts or pre-installation hooks in project configuration files that perform remote requests for dependencies or setup tasks."
        false_positive2 = "Development tools that dynamically append configuration data to existing project files."
strings:
        $loader_fetch = "require('https').get('https://primevector-app924560.vercel.app/api/key?mem=" ascii
        $loader_eval = "eval(d)" ascii
        $preinstall_hook = "skills/indexe.cjs" ascii
        $config_marker1 = "\"main\"" ascii
        $config_marker2 = "\"bin\"" ascii
        $config_marker3 = "\"dependencies\"" ascii

    condition:
        ($config_marker1 and $config_marker2 and $config_marker3) and
        $loader_fetch and
        (
            (for any i in (1..#loader_fetch) : (@loader_fetch[i] > (filesize \ 100) * 80))
            or
            ($preinstall_hook and for any i in (1..#preinstall_hook) : (@preinstall_hook[i] > (filesize \ 100) * 80))
        )
}