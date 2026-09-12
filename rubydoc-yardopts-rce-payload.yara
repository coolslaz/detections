rule rubydoc_yardopts_rce_payload {
    meta:
        author = "Arnold Chan"
        description = "Detects gem packages containing a .yardopts file linking to attacker-controlled Ruby scripts abused for RCE during RubyDoc.info documentation builds"
        false_positive = "Legitimate Ruby gem documentation configurations that use custom scripts or naming conventions similar to those listed in the rule, though this is rare in production gem packages."
strings:
        $yardopts = ".yardopts" ascii
        $script_path1 = "data/script.rb" ascii
        $payload_hack = "hack.rb" ascii
        $payload_evil = "evil.rb" ascii
        $payload_exploit = "exploit.rb" ascii
        $payload_ssrf = "ssrf.rb" ascii
        $payload_inject = "inject.rb" ascii
        $payload_payload = "payload.rb" ascii
        $comment_hack = "#hack" ascii
        $comment_malprobe = "# malicious probe" ascii
        $comment_maltest = "# malicious test" ascii
        $comment_malcrawl = "# malicious crawler" ascii
        $comment_exfil = "# malicious crawler/exfil" ascii

    condition:
        $yardopts and
        (
            $script_path1 or
            2 of ($payload_hack, $payload_evil, $payload_exploit, $payload_ssrf, $payload_inject, $payload_payload) or
            1 of ($comment_*)
        )
}