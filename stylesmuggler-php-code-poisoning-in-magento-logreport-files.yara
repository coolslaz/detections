rule StyleSmuggler_Log_Poisoning_PHP_Injection
{
    meta:
        author = "detections.ai"
        description = "Detects malicious PHP code injected into Magento var/report or var/log/system.log files as a staging mechanism for StyleSmuggler exploitation"

    strings:
        $php_open = "<?php"
        $php_short = "<?="
        $magento_report_path = "var/report/" ascii
        $magento_log_path = "var/log/system.log" ascii
        $magento_log_marker1 = "main.CRITICAL" ascii
        $magento_log_marker2 = "main.ERROR" ascii
        $eval_call = "eval(" ascii
        $base64_decode = "base64_decode" ascii
        $system_call = "system(" ascii
        $shell_exec = "shell_exec(" ascii

    condition:
        (any of ($php_open, $php_short)) and
        (any of ($magento_report_path, $magento_log_path, $magento_log_marker1, $magento_log_marker2)) and
        (any of ($eval_call, $base64_decode, $system_call, $shell_exec))
}