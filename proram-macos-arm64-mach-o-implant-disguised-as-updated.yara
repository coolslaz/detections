rule ProRAM_macOS_ARM64_Implant {
    meta:
        author = "detections.ai"
        description = "Detects the ProRAM ARM64 Mach-O implant delivered from d1u70y867zmoi6.cloudfront.net/helper and executed as $HOME/updated"
        threat_actor = "Funnull"
        malware = "ProRAM"

    strings:
        $_macho_arm64_magic = { CF FA ED FE }
        $_macho_arm64_magic_be = { FE ED FA CF }

        $codesign_id = "proram_macos_agent" ascii
        $download_url = "d1u70y867zmoi6.cloudfront.net/helper" ascii wide nocase
        $drop_path = "/updated" ascii wide
        $pro_ram1 = "ProRAM" ascii wide
        $pro_ram2 = "PRO_RAM" ascii wide

    condition:
        ($_macho_arm64_magic at 0 or $_macho_arm64_magic_be at 0) and
        (
            $codesign_id or
            $download_url or
            (any of ($pro_ram1, $pro_ram2) and $drop_path)
        )
}