rule koktevrat_obfuscated_components : koktevrat android {
    meta:
        author = "Arnold Chan"
        description = "Detects Koktevrat Android RAT APK artifacts via obfuscated component class names (JyfNnJyj, GtVyayDo) and the Stage 2 package identifier com.kowo.ciligeci"
        malware = "koktevrat"
        reference = "https://detections.ai/inspirations/01a0af5c-1c7d-701c-9759-146eb66d2454?context=user:37d6eaf6-84ff-4621-9d5c-c40051cc2b71"
        false_positive = "Legitimate Android applications that happen to use similar obfuscation naming schemes or package naming patterns by coincidence."
strings:
        $_dex_magic = "dex\n03"

        $c2_component = "JyfNnJyj" ascii
        $accessibility_component = "GtVyayDo" ascii
        $stage2_pkg = "com.kowo.ciligeci" ascii

    condition:
        $_dex_magic at 0 and 2 of ($c2_component, $accessibility_component, $stage2_pkg)
}