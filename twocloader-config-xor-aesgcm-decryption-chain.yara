rule twocloader_config_xor_aesgcm_decryption_chain {
    meta:
        author = "Arnold Chan"
        description = "Detects 2CLoader samples containing the embedded config magic bytes alongside rolling-XOR, AES-GCM, and sha256-seed-derived key material used in its payload decryption chain"
        reference = "https://www.zscaler.com"
        false_positive1 = "Legitimate security research tools or malware analysis sandboxes containing unpacked samples of the malware."
        false_positive2 = "Custom administrative scripts or utilities that happen to use similar configuration structures or naming conventions by coincidence."
strings:
        $_mz = { 4D 5A }

        // 2CLoader config magic bytes marking the config structure
        $config_magic = { 2C 3D 4E 5F }

        // Config field / variable names referenced in the decryption chain
        $f_rolling_xor = "rolling_xor_seed" ascii
        $f_aes_nonce = "aes_gcm_nonce" ascii
        $f_aes_tag = "aes_gcm_tag" ascii
        $f_seed_xor1 = "sha256_seed_xor1" ascii
        $f_seed_xor2 = "sha256_seed_xor2" ascii
        $f_checksum = "sum_of_bytes_checksum" ascii

    condition:
        $_mz at 0 and
        filesize > 50KB and filesize < 5MB and
        $config_magic and
        $f_rolling_xor and
        $f_aes_nonce and
        $f_aes_tag and
        2 of ($f_seed_xor1, $f_seed_xor2, $f_checksum)
}