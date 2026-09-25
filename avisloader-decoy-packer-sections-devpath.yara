import "pe"

rule avisloader_decoy_packer_sections_devpath {
    meta:
        author = "Arnold Chan"
        description = "Detects AvisLoader Windows loader requiring both decoy non-executable packer-named sections and an embedded c-toxcore developer build path to co-occur in a valid PE"
        malware = "AvisLoader"
        false_positive1 = "Legitimate software development tools or utilities that might contain similar local file system path structures for testing purposes."
        false_positive2 = "Packer tools or protective wrappers that use similar naming conventions and structure for legitimate obfuscation."
strings:
        $devpath = "C:\\Users\\dev\\Desktop\\c-toxcore" ascii wide
        $sec_themida = "Themida" ascii wide
        $sec_vmprotect = "VMProtect" ascii wide
        $sec_enigma = "Enigma" ascii wide
        $sec_upx = "UPX" ascii wide

    condition:
        pe.is_pe and
        pe.number_of_sections >= 15 and
        $devpath and
        2 of ($sec_themida, $sec_vmprotect, $sec_enigma, $sec_upx) and
        for any i in (0..pe.number_of_sections - 1) : (
            (pe.sections[i].name == ".Themida" or pe.sections[i].name == ".vmp0" or
             pe.sections[i].name == ".vmp1" or pe.sections[i].name == ".enigma1" or
             pe.sections[i].name == "UPX0" or pe.sections[i].name == "UPX1") and
            not (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE)
        ) and
        for any j in (0..pe.number_of_sections - 1) : (
            (pe.sections[j].name == ".Themida" or pe.sections[j].name == ".vmp0" or
             pe.sections[j].name == ".vmp1" or pe.sections[j].name == ".enigma1" or
             pe.sections[j].name == "UPX0" or pe.sections[j].name == "UPX1") and
            pe.sections[j].name != (
                for any k in (0..pe.number_of_sections - 1) : (
                    pe.sections[k].name
                )
            )
        ) == false
}