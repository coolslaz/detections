rule vidar_vm_bytecode_string_deobfuscation {
    meta:
        author = "Arnold Chan"
        description = "Detects Vidar Stealer v2.x-3.x custom VM bytecode interpreter used to deobfuscate strings via a fetch-decode-execute loop with sparse opcode dispatch and single accumulator"
        false_positive1 = "Legitimate software utilizing custom virtual machine-based protection for intellectual property protection (less common)."
        false_positive2 = "Files containing similar bytecode patterns that happen to overlap with the detection criteria."
strings:
        $_mz = { 4D 5A }

        // Example VM bytecode sequence decoded into 'браузеров найдено: %d'
        $vm_bytecode_sample = { C5 4F C7 51 24 39 F1 E6 F1 51 }

        // Vidar VM opcode set: XOR const, add next byte, ROR 2, sbox lookup, decode+emit+feedback
        $vm_op_xor = { F1 }
        $vm_op_add = { C5 }
        $vm_op_ror2 = { C7 }
        $vm_op_sbox = { 3F }
        $vm_op_emit = { 51 }

        // Strings decoded by the VM/stream cipher chain that indicate grabber output
        $decoded_str_ru = "браузеров найдено: %d" wide
        $decoded_str_grabber = "browsers: %d (%d rules), wallets: %d (%d rules), plugins: %d (%d wallet / %d plugins / %d soft), grabber: %d" ascii

    condition:
        $_mz at 0
        and (
            $vm_bytecode_sample
            or (4 of ($vm_op_*) and (#vm_op_xor + #vm_op_add + #vm_op_ror2 + #vm_op_sbox + #vm_op_emit) > 20)
            or any of ($decoded_str_*)
        )
}