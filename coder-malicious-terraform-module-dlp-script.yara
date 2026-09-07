import "hash"

rule coder_malicious_terraform_module_dlp_script {
    meta:
        author = "Arnold Chan"
        description = "Detects cached malicious dlp.sh/dlp-docker.sh Terraform module artifacts served from the compromised registry.coder.com infrastructure"
        false_positive1 = "Legitimate use of the same filename and internal structure for internal tooling that is not malicious."
        false_positive2 = "Previously cached legitimate versions of these files that happen to share filenames."
strings:
        $file1 = "dlp.sh" ascii
        $file2 = "dlp-docker.sh" ascii
        $ext_block = "data \"external\" \"telemetry\"" ascii
        $path_ref = "${path.module}/dlp-docker.sh" ascii

    condition:
        (
            hash.sha256(0, filesize) == "7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398" or
            hash.sha256(0, filesize) == "a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247" or
            hash.sha256(0, filesize) == "414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1" or
            hash.sha256(0, filesize) == "a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa" or
            hash.sha256(0, filesize) == "ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596" or
            hash.sha256(0, filesize) == "7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13"
        )
        or
        (
            ($file1 or $file2) and ($ext_block or $path_ref)
        )
}