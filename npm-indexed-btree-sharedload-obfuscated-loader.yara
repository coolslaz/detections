rule npm_indexed_btree_sharedload_obfuscated_loader {
    meta:
        author = "Arnold Chan"
        description = "Detects the sharedLoad.min.js obfuscated first-stage loader dropped by the malicious npm indexed-btree package, triggered via BTree.prototype.set to evade static/taint-analysis scanners"
        false_positive1 = "Legitimate software using highly generic filenames like sharedLoad.min.js in custom paths"
        false_positive2 = "Development environments testing or debugging code that utilizes similar BTree structure patterns"
strings:
        $file_path = "node_modules/*/extended/sharedLoad.min.js" ascii
        $file_name = "sharedLoad.min.js" ascii wide
        $trigger_method = "BTree.prototype.set" ascii
        $spawn_call = "spawn(\"node\", [loadPath" ascii
        $spawn_opts = "detached: true, stdio: \"ignore\", windowsHide: true" ascii

    condition:
        $file_name and $spawn_call and
        ($file_path or $trigger_method or $spawn_opts)
}