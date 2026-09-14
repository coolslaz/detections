import "hash"

rule kataru_known_binaries_strings_hashes {
    meta:
        author = "Arnold Chan"
        description = "Detects known KATARU IoT malware binaries via embedded strings and known SHA-256 hashes"
        malware = "KATARU"
        reference1 = "https://cybersecuritynews.com/new-kataru-iot-malware/"
        reference2 = "https://www.nozominetworks.com/blog/kataru-iot-malware-adopts-public-lpe-exploits"
strings:
        $family_str = "KATARU\x00" ascii
        $bothash_section = ".bothash" ascii
        $persist_str = "network-dispatch" ascii
        $filename = "vlxx.arm" ascii

    condition:
        any of ($family_str, $bothash_section, $persist_str, $filename)
        or hash.sha256(0, filesize) == "cc76bc218627279ecb4d0ce74ad2651e9db9e3e843e35d6569576e056e3a9218"
        or hash.sha256(0, filesize) == "13382c16e2401b07451577b46e634b8031ec254d98b876e59692b5fa22abc1d4"
        or hash.sha256(0, filesize) == "6fbae3505ae0d638b820165c572d548ce92dda71e82dc47e8efe13f30617f35f"
        or hash.sha256(0, filesize) == "9d87e6615c810907443ebd5e915f3b35099c3b5c6b6c684637138a7f8ec9cebc"
        or hash.sha256(0, filesize) == "9d7cd4948a1fcbaeadc425752fce9a933bd6fc41eeede030dffd7b99b3bc51d5"
}