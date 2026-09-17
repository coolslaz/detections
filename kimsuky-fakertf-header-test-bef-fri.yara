rule kimsuky_fakertf_header_test_bef_fri {
    meta:
        author = "Arnold Chan"
        description = "Detects the Kimsuky second-stage payload test.bef_fri which masquerades as an RTF file via a falsified RTF header before header repair and decompression"
        hash = "7479bedf5813a1527199f8958e898d19"
        false_positive = "Legitimate RTF files that happen to be named 'test.bef_fri' by users or testing processes."
strings:
        $filename = "test.bef_fri" ascii wide nocase
        $rtf_magic = { 7B 5C 72 74 66 31 }

    condition:
        ($rtf_magic at 0 and $filename)
        or hash.md5(0, filesize) == "7479bedf5813a1527199f8958e898d19"
}