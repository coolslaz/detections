rule bragjack_extension_manifest_ai_vendor_hijack {
    meta:
        author = "Arnold Chan"
        description = "Detects browser extension manifest.json files requesting declarativeNetRequest and content_scripts/host_permissions covering AI assistant vendor domains (BragJack attack class)"
        reference1 = "https://thehackernews.com/2026/09/one-extension-could-hijack-ai.html"
        reference2 = "https://forever.security/blog/bragjack-hijacking-5-browsers-via-built-in-ai-assistants"
        false_positive1 = "Legitimate browser extensions developed by AI vendors that require deep integration with their own services for browser-based AI features."
        false_positive2 = "Development and testing of custom browser extensions that involve AI assistant domains."
strings:
        $perm_dnr = "declarativeNetRequest" ascii
        $perm_cs_key = "content_scripts" ascii
        $perm_host_key = "host_permissions" ascii

        $_manifest_marker = "manifest_version" ascii

        $host_perm_ai = /"host_permissions"\s*:\s*\[[^\]]{0,600}(gemini\.google\.com|perplexity\.ai|opera\.com|claude\.ai|copilot\.microsoft\.com|testing\.perplexity\.com)/ nocase
        $matches_ai = /"matches"\s*:\s*\[[^\]]{0,600}(gemini\.google\.com|perplexity\.ai|opera\.com|claude\.ai|copilot\.microsoft\.com|testing\.perplexity\.com)/ nocase

    condition:
        $_manifest_marker and
        $perm_dnr and
        $perm_cs_key and
        $perm_host_key and
        ($host_perm_ai or $matches_ai)
}