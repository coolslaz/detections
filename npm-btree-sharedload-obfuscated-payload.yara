rule npm_btree_sharedload_obfuscated_payload {
    meta:
        author = "Arnold Chan"
        description = "Detects the obfuscated first-stage JavaScript payload sharedLoad.min.js dropped by the malicious npm indexed-btree package, identified by string-array encoding and self-checksumming array rotation obfuscation patterns"
        false_positive1 = "Legitimate JavaScript projects that use obfuscator.io for code protection or intellectual property hiding"
        false_positive2 = "Development or testing environments using similar obfuscation patterns in build processes"
strings:
        $filename = "sharedLoad.min.js" ascii

        // string-array encoding / obfuscator.io style hex-named variables and functions
        $hexvar1 = /_0x[a-f0-9]{4,6}\s*=\s*\[/ ascii
        $hexvar2 = /function\s+_0x[a-f0-9]{4,6}\s*\(/ ascii

        // self-checksumming array rotation loop pattern (obfuscator.io self-defending)
        $rotate1 = "while (!![])" ascii
        $rotate2 = "['push']" ascii
        $rotate3 = "['shift']()" ascii

        // string decoding helper commonly used with these obfuscators
        $decode1 = "parseInt(_0x" ascii
        $decode2 = "String['fromCharCode']" ascii

    condition:
        $filename and
        4 of ($hexvar1, $hexvar2, $rotate1, $rotate2, $rotate3, $decode1, $decode2)
}