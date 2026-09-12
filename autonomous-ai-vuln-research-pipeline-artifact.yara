rule autonomous_ai_vuln_research_pipeline_artifact {
    meta:
        author = "Arnold Chan"
        description = "Detects text/report artifacts (markdown, JSON, plain text) produced by an autonomous AI-driven vulnerability research pipeline that decompiles binaries, traces cross-references, hypothesizes memory-safety flaws, and generates/debugs proof-of-concept exploits"
        false_positive1 = "Legitimate security research reports or developer documentation describing manual vulnerability research processes"
        false_positive2 = "Capture-the-flag (CTF) write-ups that use similar terminology for educational purposes"
        false_positive3 = "Automated bug bounty scanner reports that contain similar vulnerability terminology"
strings:
        $decompile = "decompiled functions" ascii wide nocase
        $xref = "cross-reference" ascii wide nocase
        $hypo = "memory-safety" ascii wide nocase
        $poc = "proof-of-concept exploit" ascii wide nocase
        $iterate = "iterating until exploitable" ascii wide nocase
        $reachable = "reachable inputs" ascii wide nocase

        $_mz_header = { 4D 5A }
        $_elf_header = { 7F 45 4C 46 }
        $_pdf_header = "%PDF-"
        $_md_marker = /^#{1,6}[ \t]/

    condition:
        filesize < 20MB
        and not $_mz_header at 0
        and not $_elf_header at 0
        and not $_pdf_header at 0
        and ($_md_marker at 0 or filesize < 5MB)
        and $iterate
        and 3 of ($decompile, $xref, $hypo, $poc, $reachable)
}