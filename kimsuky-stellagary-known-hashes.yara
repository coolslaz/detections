import "hash"

rule kimsuky_stellagary_known_hashes {
    meta:
        author = "Arnold Chan"
        description = "Detects known malicious files associated with Kimsuky (APT-C-55) Stella_Gary attack chain by MD5 hash: OrionQuests-Setup.exe installer, guide.url.lnk, test.bef_fri, and backdoor payload component"
        actor = "Kimsuky, APT-C-55, BabyShark"

    condition:
        hash.md5(0, filesize) == "04272144d33668f99f7cf2255289e351" or
        hash.md5(0, filesize) == "3c64c75c9e6a3da7fbc766deb2081219" or
        hash.md5(0, filesize) == "7479bedf5813a1527199f8958e898d19" or
        hash.md5(0, filesize) == "9ae48e0ce0dfcac0245237fa220dd52d"
}