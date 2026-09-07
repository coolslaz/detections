rule jsceal_embedded_rsa_public_key {
    meta:
        author = "Arnold Chan"
        description = "Detects a hardcoded PEM RSA public key embedded alongside JSCeal-specific compiled V8 bytecode obfuscation artifacts, used to encrypt exfiltrated data or C2 communications"
        false_positive = "Legitimate applications that use custom JavaScript obfuscation and RSA encryption for security, which may share similar string artifacts."
strings:
        $pem_pub = "-----BEGIN PUBLIC KEY-----" ascii wide

        $jsc1 = "hBPBb" ascii wide
        $jsc2 = "qbyOP" ascii wide
        $jsc3 = "ykkYm" ascii wide
        $preflight = "preflight.js" ascii wide
        $app_jsc = "app.jsc" ascii wide

    condition:
        $pem_pub and (
            $preflight or
            $app_jsc or
            2 of ($jsc1, $jsc2, $jsc3)
        )
}