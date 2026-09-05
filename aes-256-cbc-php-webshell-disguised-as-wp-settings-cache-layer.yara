rule PHP_Webshell_AES_CBC_WPCacheLayer
{
    meta:
        author = "detections.ai"
        description = "Detects AES-256-CBC encrypted PHP webshell reading from php://input, executing via shell_exec, disguised as WordPress cache class"
        reference = "T1505.003"

    strings:
        $comment = "WP Settings Class - Cache Layer" ascii
        $php_input = "php://input" ascii
        $aes_cbc = "aes-256-cbc" ascii
        $decrypt = "openssl_decrypt" ascii
        $encrypt = "openssl_encrypt" ascii
        $shell_exec = "shell_exec" ascii
        $key_hardcode = "hEIBpsGVaSXyOisT//TDJd072pV8vLWSqKCq7KDXFP8=" ascii

        $_php_open = "<?php" ascii

    condition:
        $_php_open at 0 and
        $comment and
        $php_input and
        $aes_cbc and
        $decrypt and
        $shell_exec and
        (2 of ($encrypt, $key_hardcode))
}