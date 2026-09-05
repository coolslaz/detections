rule malicious_postscript_disguised_as_png {
  meta:
    author = "detections.ai"
    description = "Detects a file with a PNG header but containing embedded PostScript instructions, indicative of a Ghostscript/Imagick RCE payload disguised as an image upload (WordPress 7.0.4 fix)"
  strings:
    $_png_header = { 89 50 4E 47 0D 0A 1A 0A }
    $ps_marker1 = "%!PS-Adobe" ascii
    $ps_marker2 = "%!PS" ascii
    $ps_op_eexec = "eexec" ascii
    $ps_op_userdict = "userdict" ascii
    $ps_op_currentfile = "currentfile" ascii
    $ps_op_exec = "exec" ascii
  condition:
    $_png_header at 0 and
    (
      $ps_marker1 or
      $ps_marker2 or
      2 of ($ps_op_eexec, $ps_op_userdict, $ps_op_currentfile, $ps_op_exec)
    )
}