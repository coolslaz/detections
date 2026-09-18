dataset = xdr_data
| filter event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.NETWORK)
| filter _time >= "2026-08-01T00:00:00Z" and _time <= "2026-12-31T23:59:59Z"
| alter MatchedIndicator = coalesce(action_file_md5, action_file_sha256, action_process_image_sha256, action_remote_ip, dns_query_name)
| filter MatchedIndicator in ("a0b13781edd7cfdab13d79afff3c83c1", "4334bbaea8de33bf9d845e9b4e4e3bc2", "4843f9fafcae492f11e2d4d33dbb4cdd", "5310cabae3fbe6db8742849b588093f9", "70060341caf3338697a7ddfe0fb62875", "ad4643eea15ac286fa47d1131f9ef756", "d0b967571ac8a3863c7f324bf5bde99c", "d88d550d0fb8e60cffff3ea61ff7a067", "193.23.118.155", "208.64.33.90", "208.94.246.53", "deadhub.org")
| sort desc _time