import "pe"

rule kimsuky_stellagary_reflective_loader {
    meta:
        author = "Arnold Chan"
        description = "Detects the Stella_Gary .NET backdoor loader used by Kimsuky/APT-C-55, identified by managed-layer reflective assembly loading strings (loader.Program.Main, AssemblyResolve callback, Stella_Gary.Program.Main)"
        threat_actor = "Kimsuky, APT-C-55, BabyShark"
        false_positive1 = "Legitimate .NET applications that use obfuscators or custom loaders that happen to share naming conventions with the Stella_Gary malware components."
        false_positive2 = "Internal development tools or custom security testing utilities that implement similar managed-layer assembly loading mechanisms."
strings:
        $_mz = { 4D 5A }
        $family = "Stella_Gary" ascii wide
        $entry = "loader.Program.Main" ascii wide
        $target = "Stella_Gary.Program.Main" ascii wide
        $resolve = "AssemblyResolve" ascii wide
        $getresult = "GetAwaiter" ascii wide

    condition:
        $_mz at 0 and $family and $entry and $target and $resolve and $getresult
}