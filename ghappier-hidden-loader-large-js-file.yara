rule ghappier_hidden_loader_large_js_file {
    meta:
        author = "Arnold Chan"
        description = "Detects the GHAPPIER loader payload concealed as a single line deep inside a large (~99KB) legitimate-looking JavaScript file, fetching and eval'ing remote code"
        hash = "f2c8234c00b1f5b0b135534bf51207dc0239647890b73531996d60c90cf9e866"
        false_positive1 = "Legitimate JavaScript files that happen to be within the 90KB-110KB range and utilize 'require('https')' for external API communication, particularly if they also perform dynamic code evaluation."
        false_positive2 = "Build tools or automation scripts that might exhibit similar behavior during legitimate development or deployment processes."
strings:
        $loader_get = "require('https').get('https://primevector-app924560.vercel.app/api/key?mem=" ascii
        $eval_call = "eval(d)" ascii
        $https_require = "require('https')" ascii
    condition:
        filesize > 90KB and filesize < 110KB and
        $loader_get and $eval_call and $https_require
}