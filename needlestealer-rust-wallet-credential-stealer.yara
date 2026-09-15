rule needlestealer_rust_wallet_credential_stealer {
    meta:
        author = "Arnold Chan"
        description = "Detects NeedleStealer Rust-based stealer binaries via Go module path strings, C2 domain, build tag, and embedded browser wallet extension identifiers"
        malware = "NeedleStealer"
        campaign = "GAPI_Update"
        false_positive1 = "Legitimate software utilizing similar open-source libraries or module names that may overlap with NeedleStealer internal project naming conventions."
        false_positive2 = "Security research tools or analysis sandboxes that might contain similar binary strings or wallet-related keywords."
strings:
        $mod1 = "needle-app" ascii
        $mod2 = "needle-app/internal/api" ascii
        $c2 = "diegovalanire.digital" ascii nocase
        $buildtag = "fe9dd150d4389cc4" ascii

        $wallet1 = "MetaMask" ascii wide
        $wallet2 = "Phantom" ascii wide
        $wallet3 = "Rabby" ascii wide
        $wallet4 = "Keplr" ascii wide
        $wallet5 = "OKX" ascii wide
        $wallet6 = "Coinbase Wallet" ascii wide
        $wallet7 = "Trust Wallet" ascii wide

        $_mz = { 4D 5A }

    condition:
        $_mz at 0 and
        any of ($mod*, $c2, $buildtag)
}