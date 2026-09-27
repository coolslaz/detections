import "pe"

rule kothamine_agent_embedded_aesgcm_key {
  meta:
    author = "Arnold Chan"
    description = "Detects Kothamine Agent via hardcoded base64 AES-GCM key combined with C2 loop markers and plugin command strings, gated on PE structure to reduce false positives"
    false_positive1 = "Security research tools or malware analysis labs simulating the Kothamine Agent for testing purposes."
    false_positive2 = "Legitimate software utilizing similar command strings or encryption keys that happen to overlap with the specific hardcoded strings identified."
strings:
    $_mz = { 4D 5A }

    $aes_key = "mrowPsW2P5kzFGCNWeKAd+kYpo8Yy5c2pzaOSRuzisU=" ascii wide

    $c2_marker1 = "run_c2_loop" ascii
    $c2_marker2 = "KEEPALIVE" ascii nocase
    $c2_marker3 = "auth_token" ascii

    $cmd1 = "writefile_chunk" ascii
    $cmd2 = "writefile_start" ascii
    $cmd3 = "load_feature" ascii
    $cmd4 = "unload_feature" ascii
    $cmd5 = "list_features" ascii
    $cmd6 = "exec_feature" ascii

  condition:
    pe.is_pe and
    $_mz at 0 and
    filesize > 50KB and filesize < 50MB and
    $aes_key and
    2 of ($c2_marker*) and
    2 of ($cmd*)
}