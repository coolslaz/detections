import "hash"

rule StyleSmuggler_Rust_Implant_ELF
{
    meta:
        author = "detections.ai"
        description = "Detects the statically-linked Rust implant deployed via StyleSmuggler exploitation, disguised as a Linux kernel thread and using gvfsd-user naming and Redis session access"
        malware = "StyleSmuggler"

    strings:
        $_elf_magic = { 7F 45 4C 46 }

        $kthread_name = "[kworker/u:8:0]"
        $gvfsd_bin = "gvfsd-user"
        $gvfsd_dir = ".gvfsd"
        $gvfsd_lock = ".gvfsd_"
        $redis_ref = "redis" nocase ascii

        $hash1 = "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7" ascii wide nocase
        $hash2 = "b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420" ascii wide nocase

    condition:
        $_elf_magic at 0 and
        (
            2 of ($kthread_name, $gvfsd_bin, $gvfsd_dir, $gvfsd_lock, $redis_ref)
            or any of ($hash1, $hash2)
            or hash.sha256(0, filesize) == "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7"
            or hash.sha256(0, filesize) == "b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420"
        )
}