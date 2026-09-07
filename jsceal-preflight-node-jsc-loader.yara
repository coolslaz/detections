rule jsceal_preflight_node_jsc_loader {
    meta:
        author = "Arnold Chan"
        description = "Detects scripts or files referencing the JSCeal loading chain that invokes node.exe with -r preflight.js to decompress and execute a compiled V8 bytecode app.jsc payload"
        false_positive = "Legitimate Node.js applications that utilize V8 bytecode compilation (e.g., for code obfuscation or performance) for standard software distribution."
strings:
        $cmd1 = "node.exe -r .\\preflight.js .\\app.jsc" ascii wide nocase
        $cmd2 = "-r .\\preflight.js" ascii wide nocase
        $preflight = "preflight.js" ascii wide nocase
        $jsc = "app.jsc" ascii wide nocase
        $nodezip = "node.zip" ascii wide nocase
        $buildzip = "build.zip" ascii wide nocase
        $brotli = "brotli" ascii wide nocase

    condition:
        $cmd1 or
        ($cmd2 and $jsc) or
        (($preflight or $jsc) and (($preflight and $jsc) or 1 of ($nodezip, $buildzip, $brotli)))
}