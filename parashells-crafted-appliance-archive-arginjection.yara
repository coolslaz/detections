rule parashells_crafted_appliance_archive_arginjection {
    meta:
        author = "Arnold Chan"
        description = "Detects a Parallels appliance tar archive containing a directory entry name with an embedded double-quote character followed by the --use-compress-program flag, characteristic of the ParaShells (CVE-2026-90894) tar argument-injection payload"
        reference = "CVE-2026-90894"
        false_positive = "Legitimate tar archives that contain filenames with literal double-quote characters followed by strings resembling compression program arguments."
strings:
        $_tar_magic = "ustar" ascii
        $inject_full = "\" --use-compress-program=" ascii
        $quote_before_flag = /"[[:space:]]*--use-compress-program=/ ascii

    condition:
        // Dropped the standalone ("--use-compress-program=" + "sVmParentPath" present anywhere)
        // branch -- those two strings can co-occur in a benign appliance archive without an
        // actual injected quote, which was the real exploit signature.
        $_tar_magic and ( $inject_full or $quote_before_flag )
}