import "pe"

rule sectoprat_net_calliobfuscation_stringdecrypthelper {
    meta:
        author = "Arnold Chan"
        description = "Detects the reflectively-loaded SectopRAT .NET payload by its combination of heavy calli (indirect call) opcode usage for control-flow flattening and its characteristic runtime string-decryption helper method used to resolve the C2 IP/port and other obfuscated strings"
        false_positive = "Legitimate .NET applications that use heavy obfuscation or protection software (e.g., ConfuserEx) which might utilize similar calli-based control-flow flattening techniques."
strings:
        // structural: this must be a .NET PE (COR20 header present via pe module condition)
        $_mz = { 4D 5A }

        // calli IL opcode (0x29) preceded by a metadata token operand pattern typical of
        // method-pointer indirection used instead of direct call/callvirt
        $calli_pattern = { 29 [3] 06 }

        // characteristic decompiled helper name used across the flattened payload to
        // decrypt embedded strings (class names, C2 IP, JSON field values) by key
        $str_decrypt_helper = "c_get_str_by_key" ascii wide

        // random trash identifier embedded by the obfuscator/builder and observed in
        // decrypted InitMessage traffic emitted by this payload
        $random_trash_marker = "random_system_trash_" ascii wide

    condition:
        pe.is_pe and
        $_mz at 0 and
        pe.imports("mscoree.dll") and
        #calli_pattern > 20 and
        ($str_decrypt_helper and $random_trash_marker)
}