rule koktevrat_stage1_dropper_femam_wudemr {
    meta:
        author = "Arnold Chan"
        description = "Detects Koktevrat Stage 1 dropper (femam.apk / MandatGO) that decrypts and installs the encrypted wudEMR.apk secondary payload using a 3-byte XOR key"
        malware = "Koktevrat"
        reference = "https://detections.ai/inspirations/01a0af5c-1c7d-701c-9759-146eb66d2454"
        false_positive1 = "Security research tools or analysis sandboxes that contain similar XOR artifacts for demonstration purposes"
        false_positive2 = "Development tools that use reflection for legitimate obfuscation or modular component loading in Android applications"
strings:
        $payload_name = "wudEMR.apk" ascii wide
        $dropper_name = "femam.apk" ascii wide
        $mandatgo = "MandatGO" ascii wide nocase
        $xor_key = { 20 11 2E }
        $refl1 = "java.lang.reflect.Method" ascii
        $refl2 = "getDeclaredMethod" ascii
        $refl3 = "invoke" ascii
        $install_pkg = "REQUEST_INSTALL_PACKAGES" ascii
    condition:
        $payload_name and
        $xor_key and
        (
          $dropper_name or
          $mandatgo
        )
}