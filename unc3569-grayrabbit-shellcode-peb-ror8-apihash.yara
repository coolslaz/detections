rule unc3569_grayrabbit_shellcode_peb_ror8_apihash {
    meta:
        description = "Detects UNC3569/GRAYRABBIT shellcode combining call/pop self-location, PEB InLoadOrderModuleList walk, and the specific XOR-then-ROR8 export-name hashing loop observed in the GRAYRABBIT loader chain, requiring multiple distinctive elements together to reduce false positives on generic shellcode idioms"
        author = "Arnold Chan"
        date = "2026-09-11"
        mitre_attack = "T1027.007, T1106"
        false_positive1 = "Custom packers or obfuscators for legitimate software that implement similar ROR8 or XOR hashing algorithms for string obfuscation"
        false_positive2 = "Security research tools that manually implement shellcode loading techniques for testing purposes"
strings:
        // Classic call/pop self-locating technique: E8 00 00 00 00 followed by pop reg
        $_call_pop = { E8 00 00 00 00 ( 58 | 59 | 5A | 5B | 5C | 5D | 5E | 5F ) }

        // 32-bit PEB access via FS segment at offset 0x30
        $peb_fs30 = { 64 A1 30 00 00 00 }

        // 64-bit PEB access via GS segment at offset 0x60
        $peb_gs60 = { 65 48 8B 04 25 60 00 00 00 }

        // Consecutive [reg+0Ch] dereferences: PEB->Ldr (0x0C) then Ldr->InLoadOrderModuleList (0x0C)
        $ldr_chain_32 = { 8B ?? 0C 8B ?? 0C }

        // GRAYRABBIT-specific hashing primitive: LOBYTE(result) = *a4 ^ result; result = __ROR4__(result, 8);
        // compiled as xor reg8,mem/reg immediately followed by ror reg32,8 within the same loop body
        $grayrabbit_hash_xor_ror = { 32 ?? C1 ?? 08 }

        // ROR-by-8 instruction on general-purpose registers (export name hashing loop)
        $ror8_eax = { C1 C8 08 }
        $ror8_ecx = { C1 C9 08 }
        $ror8_edx = { C1 CA 08 }
        $ror8_ebx = { C1 CB 08 }
        $ror8_esi = { C1 CE 08 }
        $ror8_edi = { C1 CF 08 }

    condition:
        filesize > 300 and filesize < 2MB and
        $_call_pop and
        (1 of ($peb_fs30, $peb_gs60)) and
        $ldr_chain_32 and
        $grayrabbit_hash_xor_ror and
        (2 of ($ror8_*))
}