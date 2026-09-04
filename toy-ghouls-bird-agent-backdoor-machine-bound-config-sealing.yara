rule ToyGhouls_BirdAgent_Sealed_Config {
    meta:
        author = "detections.ai"
        description = "Detects Toy Ghouls mqtt-bird-agent/matrix-bird-agent backdoor binaries that seal configuration files using ChaCha20-Poly1305 keyed from HKLM MachineGuid"
        malware = "mqtt-bird-agent, matrix-bird-agent"
        threat_actor = "Toy Ghouls"

    strings:
        $_mz = { 4D 5A }

        $seal_opt = "--seal" ascii wide
        $machineguid_key = "Software\\Microsoft\\Cryptography\\MachineGuid" ascii wide nocase
        $chacha = "ChaCha20-Poly1305" ascii wide nocase
        $config = "config.toml" ascii wide nocase
        $sealedconfig_key = "Software\\synapse\\Config\\SealedConfig" ascii wide nocase
        $binary1 = "cplsupport.exe" ascii wide nocase
        $binary2 = "wtass.exe" ascii wide nocase

    condition:
        $_mz at 0 and
        (
            ($seal_opt and $machineguid_key) or
            ($chacha and $machineguid_key) or
            ($sealedconfig_key and $config) or
            (($binary1 or $binary2) and $machineguid_key)
        )
}