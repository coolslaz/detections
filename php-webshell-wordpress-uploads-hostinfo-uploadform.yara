rule php_webshell_wordpress_uploads_hostinfo_uploadform {
    meta:
        author = "Arnold Chan"
        description = "Detects PHP web shells dropped into wp-content/uploads or plugin directories following WordPress plugin exploitation, characterized by host detail reporting and a browser-based file upload form"
        reference = "https://thehackernews.com/2026/09/attackers-exploit-woocommerce-wholesale.html"
        false_positive1 = "Legitimate WordPress plugins that include administrative diagnostic tools or file management functionality."
        false_positive2 = "Custom PHP scripts developed by developers for administrative file handling or site monitoring."
        false_positive3 = "Security assessment tools or penetration testing scripts uploaded by authorized personnel."
strings:
        $_php_open = "<?php"

        $s_filename = "shell.php" ascii nocase
        $s_path_uploads = "wp-content/uploads" ascii nocase

        $s_upload_form1 = "enctype=\"multipart/form-data\"" ascii nocase
        $s_upload_form2 = "move_uploaded_file" ascii
        $s_upload_form3 = "type=\"file\"" ascii nocase

        $s_hostinfo1 = "php_uname" ascii
        $s_hostinfo2 = "gethostname" ascii
        $s_hostinfo3 = "$_SERVER['SERVER_SOFTWARE']" ascii
        $s_hostinfo4 = "$_SERVER['DOCUMENT_ROOT']" ascii

    condition:
        $_php_open and
        (
            $s_filename or
            $s_path_uploads
        ) and
        any of ($s_upload_form*) and
        any of ($s_hostinfo*)
}