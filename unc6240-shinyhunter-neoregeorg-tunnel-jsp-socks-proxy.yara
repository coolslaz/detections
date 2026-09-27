import "hash"

rule unc6240_shinyhunter_neoregeorg_tunnel_jsp_socks_proxy {
  meta:
    author = "Arnold Chan"
    description = "Detects Neo-reGeorg tunnel.jsp/tunnel.jspx servlets used by UNC6240 to establish SOCKS5-over-HTTP(S) tunneling from compromised PeopleSoft PSEMHUB.war hosts"
    false_positive1 = "Legitimate administrative tools or custom web applications that implement SOCKS or HTTP-based tunnel functionality."
    false_positive2 = "Web shells utilized for authorized penetration testing or security research."
strings:
    // Neo-reGeorg tunnel servlet code characteristics: custom command header, AES cipher usage, socket relay
    $hdr_cmd = "X-CMD" ascii
    $cipher_inst = "Cipher.getInstance" ascii
    $secretkey = "SecretKeySpec" ascii
    $socket_import = "java.net.Socket" ascii

  condition:
    (
      filesize < 51200 and
      $hdr_cmd and
      $secretkey and
      $cipher_inst and
      $socket_import
    )
    or
    hash.sha256(0, filesize) == "419c571ee38b7e7266d130c4b6bbc4dd0ef44d6e5f3bc02cc2cf73b762f07c86"
    or
    hash.sha256(0, filesize) == "ba14419beb2ec0bb94cab6298c14d7fb3e1d819366fe378290c0c2a4d97f7e07"
}