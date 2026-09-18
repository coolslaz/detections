import "pe"

rule clickfix_stealc_confuserex_obfuscated_payload {
    meta:
        author = "Arnold Chan"
        description = "Detects StealC-related .NET payload protected with ConfuserEx, requiring the sample-specific mutex string, AES key material, and multiple anti-debugging indicators together to avoid matching benign ConfuserEx-obfuscated applications"
        malware = "StealC"
        false_positive1 = "Generic applications protected with ConfuserEx that happen to share similar anti-debugging patterns."
        false_positive2 = "Legitimate software using the same mutex string or cryptographic key material."
strings:
        $mutex = "BOyBdSXJMJHWV" ascii wide
        $aes_key = "9422c81325a47a186e9a8e3841c497ba9e4d99d952ca4838e8e21b7b31427109" ascii wide
        $antidebug1 = "IsDebuggerPresent" ascii
        $antidebug2 = "CheckRemoteDebuggerPresent" ascii
        $antidebug3 = "Debugger.IsAttached" ascii wide
        $antidebug4 = "Debugger.IsLogging" ascii wide

    condition:
        pe.is_pe and
        $mutex and
        $aes_key and
        2 of ($antidebug1, $antidebug2, $antidebug3, $antidebug4)
}