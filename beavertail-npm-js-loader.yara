rule beavertail_npm_js_loader {
    meta:
        author = "Arnold Chan"
        description = "Detects BeaverTail JavaScript-based loader malware hidden inside NPM packages, distributed via GitHub or Bitbucket during fake technical interviews"
        actor = "WaterPlum"
        malware = "BeaverTail"
        false_positive1 = "Legitimate NPM packages that use postinstall/preinstall scripts for valid automation or build processes."
        false_positive2 = "Development tools or CLI utilities that legitimately require child_process to interact with external tools like curl or wget."
strings:
        $name1 = "BeaverTail" nocase ascii wide

        $postinstall = "postinstall" ascii nocase
        $preinstall = "preinstall" ascii nocase

        $node_require1 = "require('child_process')" ascii
        $node_require2 = "require(\"child_process\")" ascii

        $exec_hidden = /exec\s*\(\s*['"](curl|wget|node)/ ascii nocase

    condition:
        filesize < 500KB and
        (
            $name1
            or (
                (any of ($postinstall, $preinstall)) and
                (any of ($node_require1, $node_require2)) and
                $exec_hidden
            )
        )
}