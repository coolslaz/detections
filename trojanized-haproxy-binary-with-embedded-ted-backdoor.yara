rule HAProxy_Ted_Backdoor_Embedded {
    meta:
        author = "detections.ai"
        description = "Detects HAProxy 2.8.12 binaries recompiled with the embedded 'ted' backdoor plugin used to intercept and manipulate web traffic"
        hash = "72e70936f0dbe459142a1d867617c35f8d0cce5d18c6a49e1090a2a5adc8e558"
        hash2 = "4bb923eb040aa13ca8fd409c31ee4729c60ddff32e350efe1c5a4a9168a065f5"
    strings:
        $_elf = { 7F 45 4C 46 }
        $ted_str1 = "ted_plugin" ascii
        $ted_str2 = "ted_flt_register_ops2" ascii
        $ted_str3 = "ted_make_pipe_name" ascii
        $ted_str4 = "ted_create_multi_pipe_file" ascii
        $haproxy_ver = "2.8.12" ascii
        $cache1 = "haproxy-1000.cache" ascii
        $cache2 = "haproxy-1001.cache" ascii
        $cache3 = "haproxy-1002.cache" ascii
        $pipe = "_w.pipe" ascii
        $jasper = "/tmp/jasper-log" ascii
    condition:
        $_elf at 0 and
        (
            2 of ($ted_str1, $ted_str2, $ted_str3, $ted_str4) or
            ($haproxy_ver and 1 of ($ted_str1, $ted_str2, $ted_str3, $ted_str4)) or
            (1 of ($cache1, $cache2, $cache3) and (any of ($ted_str*) or $pipe or $jasper))
        )
}