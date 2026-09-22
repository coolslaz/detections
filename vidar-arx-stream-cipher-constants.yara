rule vidar_arx_stream_cipher_constants {
  meta:
    author = "Arnold Chan"
    description = "Detects Vidar's custom stream cipher used for string/config decryption: FNV-1a mixing of the VM-derived key combined with golden-ratio nonce mixing and per-build ARX round constants"
    false_positive1 = "Legitimate software using identical ARX-based encryption libraries or constants (e.g., specific cryptographic implementations)."
    false_positive2 = "Security research tools or malware analysis labs simulating Vidar behavior."
strings:
    $_mz = { 4D 5A }

    // FNV-1a prime 0x01000193 used to mix key into 32-bit state
    $fnv_prime = { 93 01 00 01 }

    // Golden-ratio constant 0x9E3779B9 used to mix nonce
    $golden_ratio = { B9 79 37 9E }

    // Per-build ARX round constants, v2.4 sample
    $arx_v24_1 = { C9 C2 C8 C5 }
    $arx_v24_2 = { 1E B8 76 E4 }
    $arx_v24_3 = { A0 30 7A 90 }
    $arx_v24_4 = { 5D 29 67 C9 }
    $arx_v24_5 = { 4F 76 2A A7 }

    // Per-build ARX round constants, v2.5 sample
    $arx_v25_1 = { 67 CA AC 43 }
    $arx_v25_2 = { 01 3B 1A 87 }
    $arx_v25_3 = { 6B B6 24 1D }
    $arx_v25_4 = { 2E A9 C4 9E }
    $arx_v25_5 = { F6 39 DE 9D }

  condition:
    $_mz at 0
    and $fnv_prime
    and $golden_ratio
    and (3 of ($arx_v24_*) or 3 of ($arx_v25_*))
}