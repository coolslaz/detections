import "hash"

rule vectrarat_known_sample_hashes_and_infrastructure {
    meta:
        author = "Arnold Chan"
        description = "Matches known VectraRAT sample SHA-256 hashes and the ClickFix distribution domain (verify-cloud.digital) recovered from pivoting across exposed VectraRAT distribution infrastructure"
        malware = "VectraRAT"
        reference = "https://detections.ai/inspirations/01a0a039-7d80-762c-9a8a-66239879f736?context=user:37d6eaf6-84ff-4621-9d5c-c40051cc2b71"
        false_positive1 = "Security research environments or malware analysis labs intentionally downloading or executing the identified malicious samples."
        false_positive2 = "Legitimate software that might have been compromised and repurposed to use the same infrastructure (unlikely but possible)."
strings:
        $c2_domain = "verify-cloud.digital" ascii wide nocase
        $ip1 = "86.109.75.168" ascii wide
        $ip2 = "86.109.75.161" ascii wide
        $ip3 = "178.16.54.148" ascii wide
        $ip4 = "195.20.115.77" ascii wide
        $ip5 = "91.219.236.179" ascii wide
        $ip6 = "91.92.242.236" ascii wide
        $ip7 = "195.63.145.106" ascii wide

    condition:
        hash.sha256(0, filesize) == "e2db5db12564d2a9da7ef3a57aa23d95782f5eaddc8bd35eb7c35ae6b844a0f0" or
        hash.sha256(0, filesize) == "dede8bfb55c2e6479d89b1e73e0712791cf16a7179325804fc4bc13f708d08ae" or
        hash.sha256(0, filesize) == "ddbd636f6dfd475dc0c75bf9f6f873fa35b9062dee9d37b3377ae7b9acdcd0c9" or
        hash.sha256(0, filesize) == "b926cfcd3f4b07fe6001c39f46e40225ff8000411198d13782538d770c54ae5e" or
        hash.sha256(0, filesize) == "bff3583d04f0d5603ced9831eb7c45c1923bd90e2f7d5e5d2b32942d38cf6dc5" or
        hash.sha256(0, filesize) == "c708d413720848f8788f43a4f47ddce016fca9af10c9ba4113f47bf2c9244dc5" or
        hash.sha256(0, filesize) == "8745e872ff8aa41b0e03737f76bf35b6c934106c987dff98afe34120e47caf91" or
        hash.sha256(0, filesize) == "bba58f99e14e3512c04a5a74a079d7851abf935dd258cff4c80874ce7cfc82e3" or
        hash.sha256(0, filesize) == "d8f15ba122cd6da01f83fe05294df80a6eadbce0f66dac7c2bcc0904f066e0de" or
        hash.sha256(0, filesize) == "3ab56c9fb6b7c404c1e5b36788959c877ea819fb124c3847fa0498e9915ef9a7" or
        hash.sha256(0, filesize) == "7b82f08120e0d9b16cd5b9ec59d24fb68e35735c82311a233d370e7f264af650" or
        hash.sha256(0, filesize) == "b738c03fef5e3d26419e4aab1818a0a7ad206c67fb3eeedcdfb3ef1ee07eb620" or
        any of ($c2_domain, $ip1, $ip2, $ip3, $ip4, $ip5, $ip6, $ip7)
}