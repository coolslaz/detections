rule ghappier_js_loader_https_eval {
    meta:
        author = "Arnold Chan"
        description = "Detects the GHAPPIER loader pattern: a top-level require('https').get() call to the primevector-app924560.vercel.app C2 that evals the response, disguised inside a large benign-looking JavaScript benchmark file"
        hash = "f2c8234c00b1f5b0b135534bf51207dc0239647890b73531996d60c90cf9e866"
        false_positive1 = "Legitimate JavaScript build or testing scripts that use 'https' to fetch remote configuration files, though use of 'eval()' in such contexts is rare and highly suspicious."
        false_positive2 = "Developers using 'eval()' in legitimate benchmarking code, though the specific pattern of fetching and evaluating from a remote URL is unusual in standard development."
strings:
        $c2_url = "require('https').get('https://primevector-app924560.vercel.app/api/key?mem=" ascii
        $eval_call = "eval(d)" ascii
        $data_accum = "r.on('data',c=>d+=c)" ascii
        $end_handler = "r.on('end',()=>\x7B" ascii
    condition:
        $c2_url and $eval_call and ($data_accum or $end_handler)
}