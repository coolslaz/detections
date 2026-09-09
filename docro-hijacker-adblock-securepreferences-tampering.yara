rule docro_hijacker_adblock_securepreferences_tampering {
    meta:
        author = "Arnold Chan"
        description = "Detects Adblock.dll used by Docro Hijacker to bypass Chrome Secure Preferences HMAC-SHA256 integrity checks and register infected browser UUID via vendralo[.]info"
        threat_actor = "CL-CRI-1171"
        malware = "Docro Hijacker"
        false_positive1 = "Legitimate browser extension management tools or security software that modifies browser preferences to enforce security policies or ad-blocking configurations might trigger this if they share naming conventions."
        false_positive2 = "Development or debugging tools specifically designed to interact with browser internals or local preference files."
strings:
        $mz = { 4D 5A }
        $dll_name = "Adblock.dll" ascii wide nocase
        $temp_path = "\\Temp\\Adblock.dll" ascii wide nocase
        $secure_pref = "Secure Preferences" ascii wide
        $resources_pak = "resources.pak" ascii wide nocase
        $c2_uuid = "vendralo.info" ascii wide nocase
        $hmac = "HMAC" ascii wide

    condition:
        $mz at 0 and
        filesize > 1MB and filesize < 5MB and
        all of ($dll_name, $temp_path, $secure_pref, $resources_pak, $c2_uuid, $hmac)
}