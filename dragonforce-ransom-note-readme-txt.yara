rule dragonforce_ransom_note_readme_txt {
    meta:
        author = "Arnold Chan"
        description = "Detects DragonForce ransomware note (readme.txt) referencing known DragonForce Tor negotiation/blog onion addresses"
        mitre_attack = "T1486, T1657"
        false_positive1 = "Security research activities involving the storage of ransomware samples or IOC documentation files."
        false_positive2 = "Legitimate use of a file named 'readme.txt' in software deployment or documentation if it coincidentally contains the specific hardcoded strings."
strings:
        $filename = "readme.txt" ascii wide nocase
        $onion1 = "3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd.onion" ascii wide nocase
        $onion2 = "z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion" ascii wide nocase
    condition:
        filesize < 20KB and $filename and 2 of ($onion*)
}