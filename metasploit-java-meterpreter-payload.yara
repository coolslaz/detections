rule metasploit_java_meterpreter_payload {
    meta:
        author = "Arnold Chan"
        description = "Detects Java-based Metasploit/Meterpreter payload files (.class/.jar) dropped post-exploitation, as observed following PaperCut RCE exploitation chain"
        false_positive1 = "Legitimate Java application development or testing tools containing similar strings."
        false_positive2 = "Custom Java-based administration or diagnostic tools that share dependencies with Metasploit payloads."
        false_positive3 = "Authorized security assessment or red teaming activities."
strings:
        $_class_magic = { CA FE BA BE }

        $strong1 = "metasploit/Payload" ascii
        $strong2 = "metasploit.Payload" ascii
        $strong3 = "MeterpreterHandler" ascii
        $strong4 = "metasploit/meterpreter" ascii
        $weak1 = "javapayload" ascii
        $weak2 = "JavaPayload" ascii
        $weak3 = "loadStage" ascii
        $weak4 = "connectTransport" ascii
        $weak5 = "getPayload" ascii

    condition:
        $_class_magic at 0 and
        (
            any of ($strong*) or
            3 of ($weak*)
        )
}