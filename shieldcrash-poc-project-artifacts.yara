rule shieldcrash_poc_project_artifacts {
    meta:
        author = "Arnold Chan"
        description = "Detects presence of multiple ShieldCrash CVE-2026-69414 PoC Visual Studio project/solution build artifacts indicating exploit tooling staging"
        reference = "https://detections.ai/inspirations/01a08541-c775-710c-ba08-9bf21a80aba0"
        false_positive1 = "Legitimate software development projects that happen to use the same project naming convention 'ShieldCrash'."
        false_positive2 = "Security researchers or analysts downloading or testing the PoC in an isolated laboratory environment."
strings:
        $s1 = "ShieldCrash.slnx" ascii wide nocase
        $s2 = "ShieldCrash.vcxproj" ascii wide nocase
        $s3 = "ShieldCrash.aps" ascii wide nocase
        $s4 = "ShieldCrash.rc" ascii wide nocase

    condition:
        2 of them
}