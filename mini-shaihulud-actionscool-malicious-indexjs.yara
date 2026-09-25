rule mini_shaihulud_actionscool_malicious_indexjs {
    meta:
        author = "detections.ai"
        description = "Detects the obfuscated index.js payload bundled in the compromised actions-cool/issues-helper and actions-cool/maintain-one-comment commit a0c53dd42fc842d2f9276c5a1d4f9a26abe8713d, executed via 'bun run $GITHUB_ACTION_PATH/index.js'"
        threat_actor = "Mini Shai-Hulud"
        false_positive1 = "Legitimate use of the actions-cool repository prior to or following the compromised version."
        false_positive2 = "Administrative debugging or testing of the specific actions-cool scripts."
        false_positive3 = "Use of the bun runtime in an environment where the script paths coincidently overlap."
strings:
        $commit_ref = "a0c53dd42fc842d2f9276c5a1d4f9a26abe8713d" ascii
        $bun_exec = "bun run $GITHUB_ACTION_PATH/index.js" ascii
        $action_path_var = "GITHUB_ACTION_PATH" ascii
        $bun_setup = "oven-sh/setup-bun" ascii
        $repo1 = "actions-cool/issues-helper" ascii
        $repo2 = "actions-cool/maintain-one-comment" ascii
        $_filename = "index.js" ascii

    condition:
        $_filename and
        (
            $commit_ref or
            ($bun_exec and $action_path_var and $bun_setup) or
            ($bun_exec and $action_path_var and ($repo1 or $repo2)) or
            ($bun_setup and $repo1 and $repo2)
        )
}