// Note: full SHA-256 hashes for these artifacts were not available (only truncated prefixes were reported,
// and JSP file hashes are known to vary due to extra newlines/tunnel keys), so this rule
unc6240_shinyhunter_psemhubwar_web_shell_and_installer_artifacts {
  meta:
    author = "Arnold Chan"
    description = "Detects UNC6240 PSEMHUB.war web shell/tunnel/trojanized installer artifacts by distinctive content markers (x.jsp, u.jsp, tunnel.jsp/jspx, Ple64.exe)"
    false_positive1 = "Legitimate administration scripts using similar parameter names or encoding patterns in JSP files."
    false_positive2 = "Diagnostic tools or authorized network debugging utilities that utilize SOCKS proxies."
    false_positive3 = "Legitimate software updates or installers using VMProtect or similar obfuscation techniques."
strings:
    // x.jsp: hex-encoded command execution shell, parameter c/t, output prefix R:, ASCII char-array reconstructed cmd.exe/bin/sh
    $xjsp_param_c = "request.getParameter(\"c\")" ascii
    $xjsp_param_t = "request.getParameter(\"t\")" ascii
    $xjsp_out_r = "R:" ascii
    $xjsp_chararray = /char\[\]\s*\{\s*(0x[0-9a-fA-F]{1,2}\s*,\s*){3,}\}/ ascii

    // u.jsp/u2.jsp: chunked base64 upload-and-execute stager, parameters a/m/n/x, output W:/R: prefixes
    $ujsp_param_a = "request.getParameter(\"a\")" ascii
    $ujsp_param_m = "request.getParameter(\"m\")" ascii
    $ujsp_param_n = "request.getParameter(\"n\")" ascii
    $ujsp_param_x = "request.getParameter(\"x\")" ascii
    $ujsp_out_w = "W:" ascii
    $ujsp_base64decoder = "Base64.getDecoder" ascii

    // tunnel.jsp/tunnel.jspx: Neo-reGeorg SOCKS5-over-HTTP tunnel servlet markers
    $neoreGeorg_marker1 = "X-EASY-TUNNEL-PROXY" ascii
    $neoreGeorg_marker2 = "SocketFactory" ascii
    $neoreGeorg_marker3 = "neoreg" ascii nocase

    // Ple64.exe: trojanized installer masquerading as Light Alloy media player, embedding VMP3-packed SIDEEYE loader
    $ple64_lightalloy = "Light Alloy" ascii wide
    $ple64_vmp = "VMProtect" ascii
    $ple64_signer = "Tobias Weihmann Software Development" ascii wide

  condition:
    ($xjsp_chararray and 1 of ($xjsp_param_c, $xjsp_param_t, $xjsp_out_r))
    or 3 of ($ujsp_param_a, $ujsp_param_m, $ujsp_param_n, $ujsp_param_x, $ujsp_out_w, $ujsp_base64decoder)
    or ($neoreGeorg_marker1 and 1 of ($neoreGeorg_marker2, $neoreGeorg_marker3))
    or ($ple64_signer or ($ple64_lightalloy and $ple64_vmp))
}