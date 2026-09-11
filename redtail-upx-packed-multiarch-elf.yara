import "hash"

rule redtail_upx_packed_multiarch_elf {
    meta:
        author = "Arnold Chan"
        description = "Detects RedTail malware samples: UPX-packed, statically linked ELF executables across multiple architectures (x86_64, ARM, ARM64, i686, RISC-V). Requires UPX packing signature to co-occur with RedTail-specific filename strings to reduce false positives on generic UPX-packed binaries."
        malware = "RedTail"
        reference_hash = "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
        false_positive1 = "Legitimate binaries that happen to use UPX packing and have similar filenames containing 'redtail'."
        false_positive2 = "Security research tools or analysis samples that mimic the file structure or naming conventions of RedTail."
strings:
        $_elf_magic = { 7F 45 4C 46 }

        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX executable packer" ascii

        $fname1 = "redtail.x86_64" ascii
        $fname2 = "redtail.arm7" ascii
        $fname3 = "redtail.arm8" ascii
        $fname4 = "redtail.i686" ascii
        $fname5 = "redtail.riscv" ascii

    condition:
        $_elf_magic at 0
        and (
            hash.sha256(0, filesize) == "63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e"
            or (
                any of ($upx*)
                and any of ($fname*)
            )
        )
}