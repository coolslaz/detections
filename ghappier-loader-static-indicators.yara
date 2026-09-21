rule ghappier_loader_static_indicators {
    meta:
        author = "Arnold Chan"
        description = "Detects the GHAPPIER loader identified across 65 public npm/GitHub repositories and 22 developer accounts, based on its embedded remote-fetch/eval pattern and campaign markers"
        hash = "f2c8234c00b1f5b0b135534bf51207dc0239647890b73531996d60c90cf9e866"
        false_positive1 = "Legitimate build scripts that use 'eval()' for dynamic property resolution or data parsing in uncommon development workflows."
        false_positive2 = "Developers using similar naming conventions for legitimate infrastructure markers or testing scripts in non-malicious environments."
        false_positive3 = "Packages that perform dynamic loading for legitimate modular features and utilize standard node.js 'https' module requests."
strings:
        $fetch_eval = "require('https').get('https://primevector-app924560.vercel.app/api/key?mem=" ascii
        $eval_callback = "eval(d)" ascii
        $campaign_tag_1 = "mem=ghappier" ascii
        $campaign_tag_2 = "mem=g1028" ascii
        $campaign_tag_3 = "mem=g0115" ascii
        $campaign_tag_4 = "mem=g213515" ascii
        $marker_file = ".git-checker" ascii
        $secondary_domain = "brightlaunch-ext75642.vercel.app" ascii
        $tokenapp_pkg = "tokenapp" ascii

    condition:
        filesize < 5MB and
        (
            $fetch_eval or
            (2 of ($campaign_tag_1, $campaign_tag_2, $campaign_tag_3, $campaign_tag_4)) or
            ($marker_file and $secondary_domain) or
            ($eval_callback and $tokenapp_pkg and ($secondary_domain or $marker_file or $fetch_eval))
        )
}