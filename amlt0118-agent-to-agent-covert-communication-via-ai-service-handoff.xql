// Title: Agent-to-Agent Communication — Unapproved AI Service Chaining
// MITRE ATT&CK: T1071.001, T1105, ATLAS: AML.T0118

dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_result = "SUCCESS"
| filter action_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe")
| filter dns_query_name in ("api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.together.xyz", "api.groq.com", "api.cohere.ai", "openrouter.ai")
| filter action_remote_ip != null
| filter not (action_remote_ip incidr "10.0.0.0/8" or action_remote_ip incidr "172.16.0.0/12" or action_remote_ip incidr "192.168.0.0/16" or action_remote_ip incidr "127.0.0.0/8")
| fields agent_id, agent_hostname, actor_effective_username, _time, action_process_id, action_process_image_path, action_process_command_line, dns_query_name, action_remote_ip, action_remote_port
| alter src_process_id = action_process_id, src_process_path = action_process_image_path
| join type=inner (dataset = xdr_data | filter event_type = ENUM.FILE and action_file_action in ("CREATE", "WRITE") | filter action_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe") | filter action_file_path ~= ".*[\\/](queue|shared|outbox|handoff|artifacts)[\\/].*" | fields agent_id, _time as write_time, action_process_id as writer_id, action_file_name, action_file_path) as handoff handoff.agent_id = agent_id
| filter timestamp_diff(_time, handoff.write_time, "MINUTE") >= 0 and timestamp_diff(_time, handoff.write_time, "MINUTE") <= 5
| alter composite_key = concat(agent_id, "_", handoff.action_file_name)
| join type=inner (dataset = xdr_data | filter event_type = ENUM.FILE and action_file_action = "READ" | filter action_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe") | alter composite_key = concat(agent_id, "_", action_file_name) | fields agent_id, _time as read_time, action_process_id as reader_id, action_file_name, action_file_path, composite_key) as reader reader.composite_key = composite_key
| filter reader.read_time > handoff.write_time and timestamp_diff(reader.read_time, handoff.write_time, "MINUTE") <= 5
| filter reader.reader_id != src_process_id
| dedup agent_id, src_process_id, reader.reader_id, handoff.action_file_name by asc _time
| sort asc _time