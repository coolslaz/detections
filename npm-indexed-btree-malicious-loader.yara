rule npm_indexed_btree_malicious_loader {
    meta:
        author = "Arnold Chan"
        description = "Detects the indexed-btree npm malware loader embedded in BTree.prototype.set that spawns a detached hidden Node.js child process and references sharedLoad.min.js"
        threat_actor = "North Korean hackers"
        malware = "indexed-btree, btree-core"
        campaign = "npm 'btree' Malware Campaign"
        false_positive1 = "Legitimate Node.js packages that use 'spawn' with 'detached: true' for genuine background task management or daemonization."
        false_positive2 = "Development or debugging tools that intentionally spawn child processes for testing purposes and might use similar configuration strings."
strings:
        $pkg_name = "indexed-btree" ascii
        $proto_trigger = "BTree.prototype.set" ascii
        $shared_loader = "sharedLoad.min.js" ascii
        $spawn_pattern = /spawn\s*\(\s*["']node["']\s*,\s*\[\s*loadPath/ ascii
        $spawn_opts = "detached: true, stdio: \"ignore\", windowsHide: true" ascii
        $unref = "child.unref()" ascii
    condition:
        $proto_trigger and $spawn_pattern and $spawn_opts and 1 of ($shared_loader, $unref, $pkg_name)
}