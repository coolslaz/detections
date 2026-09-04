rule Webshell_PHP_Path_Traversal_Placement {
    meta:
        author = "detections.ai"
        description = "Detects PHP files containing embedded path traversal sequences, consistent with webshells placed outside the standard wp-content/uploads directory via path traversal exploitation"
    strings:
        $php_open = "<?php" ascii
        $php_open_short = "<?" ascii
        $traversal_unix = "../../" ascii
        $traversal_win = "..\\..\\" ascii
        $traversal_encoded = "%2e%2e%2f" ascii nocase
        $traversal_encoded2 = "%2e%2e%5c" ascii nocase
    condition:
        (any of ($php_open*)) and (any of ($traversal*)) and filesize < 200KB
}