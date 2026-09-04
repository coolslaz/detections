rule Mushr00w_PHP_Webshell {
    meta:
        author = "detections.ai"
        description = "Detects the Mushr00w Uploader PHP web shell dropped into WordPress uploads directories via Super Forms/Elementor Pro RCE exploitation"
    strings:
        $filename = "Mushr00w_upl.php" ascii wide nocase
        $title = "Mushr00w Uploader" ascii wide nocase
        $title_tag = "<title>Mushr00w Uploader</title>" ascii nocase
        $upload_func = "move_uploaded_file($_FILES[\"file\"]" ascii
        $upload_func2 = "move_uploaded_file($_FILES['file']" ascii
        $css_green = "#00ff00" ascii nocase
        $css_black = "#0a0a0a" ascii nocase
        $path_hint = "wp-content/uploads" ascii nocase
        $php_tag = "<?php" ascii
    condition:
        $filename or
        (
            $php_tag and
            (
                $title or $title_tag or
                (any of ($upload_func*) and $css_green and $css_black)
            )
        )
}