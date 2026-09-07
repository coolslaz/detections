import "hash"

rule coder_dlp_sh_malicious_hash_match {
    meta:
        description = "Matches known malicious dlp.sh/dlp-docker.sh Terraform module scripts used in Coder registry supply chain attack (common, aider, rstudio-server, windows-rdp, zed variants)"
        author = "Arnold Chan"

    condition:
        hash.sha256(0, filesize) == "7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398" or
        hash.sha256(0, filesize) == "a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247" or
        hash.sha256(0, filesize) == "414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1" or
        hash.sha256(0, filesize) == "a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa" or
        hash.sha256(0, filesize) == "ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596" or
        hash.sha256(0, filesize) == "7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13"
}