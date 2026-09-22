// Title: SideCopy / Operation SideCopy / ReverseRAT known-IOC hunting rule
// Description: Matches known SHA256 hashes, C2 IP, C2/hosting domains, and malicious URLs associated with Operation SideCopy.
// MITRE ATT&CK: T1566, T1071.001, T1059

dataset = xdr_data
| alter sha256_list = arraycreate("0647336477bdd277450b0c36f104f3f82da721e98d56b67bbeeec05cc48f2d1c", "0e0b77f79fe5d06f11de2959559379e94d62512e073c267b481a58d19d265240", "34c20f5abc04375822f3f68e3e9915c7e388e8adb1ade597672920d53f2c067c", "ac340859805220f97f98b299b32d82b1ccbb2c04c8c09516f3937feda937af80", "8435ec938ca225c3131a624715832845ad9adc5faa93488486bc19c094b4d3ec", "a5e36cf05bcc9ac4e9ebf2a13f95aef8e3847086fe7340c36d6aba6616ae1174", "cceee5c983360842351ffdb8979676fd2fccd4e4c387ac77e4506291d8083c5c")
| alter malicious_url_list = arraycreate("https://docsportal.in/public/reps/com/161.php", "https://docsportal.in/public/reps/com/com.hta", "http://docsportal.in/public/reps/com/com.hta")
| filter (event_type = ENUM.FILE and action_file_sha256 in (sha256_list)) or (event_type = ENUM.PROCESS and action_process_image_sha256 in (sha256_list)) or (event_type = ENUM.NETWORK and (action_remote_ip = "45.61.157.22" or extract_url_host(action_network_http_url) ~= "(^|\\.)(docsportal\\.in|dns\\.educationportals\\.biz)$")) or (event_type = ENUM.NETWORK and action_network_http_url in (malicious_url_list))
| fields _time, agent_hostname, actor_primary_username, action_file_name, action_process_image_name, action_file_sha256, action_process_image_sha256, action_remote_ip, action_network_http_url, event_type
| sort desc _time