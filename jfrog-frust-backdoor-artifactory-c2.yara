import "pe"

rule jfrog_frust_backdoor_artifactory_c2 {
    meta:
        author = "Arnold Chan"
        description = "Detects Rust-compiled executables exhibiting C2-capable characteristics consistent with backdoors dropped on compromised JFrog Artifactory servers"
        reference = "https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html"
        false_positive = "Raised the Rust-artifact string requirement from 4 of 5 to all 5 of 5, further reducing the chance of matching a non-Rust or heavily stripped binary that happens to share only a couple of the marker strings"
strings:
        // Rust toolchain / runtime artifacts embedded by rustc in compiled binaries
        $rust1 = "rustc/" ascii
        $rust2 = "cargo/registry" ascii
        $rust3 = "library/std/src" ascii
        $rust4 = "panicked at" ascii
        $rust5 = ".rs" ascii

        // Structural check
        $_header_mz = { 4D 5A }

    condition:
        $_header_mz at 0 and
        pe.is_pe and
        5 of ($rust*) and
        pe.number_of_signatures == 0 and
        (
            pe.imports("ws2_32.dll", "connect") or
            pe.imports("ws2_32.dll", "send") or
            pe.imports("wininet.dll", "InternetConnectA")
        ) and
        pe.imports("advapi32.dll", "CreateServiceA")
}