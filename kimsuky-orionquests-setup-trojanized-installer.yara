import "hash"

rule kimsuky_orionquests_setup_trojanized_installer {
    meta:
        author = "Arnold Chan"
        description = "Detects the Kimsuky trojanized .NET installer OrionQuests-Setup.exe that decrypts embedded AES resource OrionSetup.payload.enc to drop a decoy OrionLauncher installer and malicious LNK file"
        threat_actor = "Kimsuky, APT-C-55"
        malware = "OrionQuests-Setup.exe"
        false_positive1 = "Legitimate installers that use similar naming conventions or obfuscated resource naming conventions if they happen to share the same strings (rare)."
        false_positive2 = "Security analysis software or sandbox environments that might trigger alerts if they are testing or emulating this specific malware."
strings:
        $_mz = { 4D 5A }
        $resource_name = "OrionSetup.payload.enc" ascii wide
        $filename = "OrionQuests-Setup.exe" ascii wide nocase
        $decoy1 = "OrionLauncher" ascii wide

    condition:
        $_mz at 0 and
        filesize < 20MB and
        (
            hash.md5(0, filesize) == "04272144d33668f99f7cf2255289e351" or
            ($resource_name and 1 of ($filename, $decoy1))
        )
}