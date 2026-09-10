import "hash"

rule cmd_jar_command_executor {
    meta:
        author = "Arnold Chan"
        description = "Detects cmd.jar, a JAR-based command executor used by threat actors on compromised Cisco Secure FMC to run arbitrary shell commands via /bin/sh -c"
        hash = "Db491181ece3f319de6567ab6f6daa90c6879911cd890155e6b7d8cc7a1a8c8e"
        false_positive = "Legitimate small Java utility JARs that also shell out via ProcessBuilder(\"/bin/sh\",\"-c\",...) — mitigated by requiring 2 of the executor's distinctive console-output strings plus a small filesize ceiling."
strings:
        $_pk_header = { 50 4B 03 04 }
        $filename = "cmd.jar" ascii wide fullword
        // Distinctive runtime strings from the decompiled executor's main() (Poc class), not generic Java idioms
        $exec_marker = "--- Executing: " ascii
        $exitcode_marker = "--- Exit Code: " ascii
        $usage_marker = "Usage: java -jar exploit.jar" ascii wide
        $pb = "ProcessBuilder" ascii
        $shell = "/bin/sh" ascii

    condition:
        hash.sha256(0, filesize) == "db491181ece3f319de6567ab6f6daa90c6879911cd890155e6b7d8cc7a1a8c8e"
        or (
            $_pk_header at 0 and
            filesize < 100KB and
            $pb and $shell and
            $filename and
            2 of ($exec_marker, $exitcode_marker, $usage_marker)
        )
}