rule KATARU_CVE_2026_46300_Fragnesia_Exploit {
    meta:
        author = "Arnold Chan"
        description = "Detects embedded CVE-2026-46300 (Fragnesia) Linux privilege escalation exploit code used by KATARU IoT malware, copied unmodified from public PoC"
        threat_name = "KATARU"
        cve = "CVE-2026-46300"
        reference1 = "https://cybersecuritynews.com/new-kataru-iot-malware/"
        reference2 = "https://www.nozominetworks.com/blog/kataru-iot-malware-adopts-public-lpe-exploits"
        false_positive1 = "Security research tools or proof-of-concept repositories containing the same exploit source code or compiled binaries."
        false_positive2 = "Legitimate security testing tools designed to audit for the specified CVE."
strings:
        $err_size = "target is too small: size=%lld need>=4096" ascii
        $err_prctl = "prctl PR_SET_DUMPABLE" ascii
        $err_pipe1 = "pipe ready" ascii
        $err_pipe2 = "pipe mapped" ascii
        $err_fork = "fork userns mapper" ascii

        $_elf_magic = { 7F 45 4C 46 }

    condition:
        $_elf_magic at 0 and
        filesize < 5MB and
        all of ($err_size, $err_prctl, $err_pipe1, $err_pipe2, $err_fork)
}