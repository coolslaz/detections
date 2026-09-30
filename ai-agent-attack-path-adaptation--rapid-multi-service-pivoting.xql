/*
 * Title: AI Agent Attack-Path Adaptation — Rapid Technique Switching After Failed Access
 * Description: Detects autonomous agent pivoting by correlating failed connections, subsequent credential attempts, and pivot traffic within a tight timeframe. Excludes known authorized red-team/pentest and scanner accounts.
 * MITRE ATT&CK: T1190, T1210, T1078
 * MITRE ATLAS: AML.T0117
 * Author: Arnold Chan
 */

dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter event_sub_type = ENUM.NETWORK_CONNECTION
| filter action_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe")
| filter causality_actor_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe")
| filter actor_effective_username not in ("svc_redteam", "svc_pentest", "svc_vulnscan", "nessus", "qualys") and not (actor_effective_username ~= "(?i)^(svc_pentest|svc_redteam|svc_vulnscan)$")
| alter ServiceCategory = if(action_remote_port in (445, 139), "SMB", if(action_remote_port = 22, "SSH", if(action_remote_port in (80, 443), "HTTP", if(action_remote_port = 3389, "RDP", if(action_remote_port in (5985, 5986), "WinRM", "")))))
| filter ServiceCategory != ""
| alter JoinKey = concat(agent_id, "_", causality_actor_process_id, "_", to_string(causality_actor_process_creation_time))
| bin _time span = 5m
| comp count_distinct(ServiceCategory) as DistinctServices, values(ServiceCategory) as Services, count_distinct(action_remote_ip) as DistinctTargets, values(action_remote_ip) as TargetsAttempted, earliest(_time) as FirstFail, latest(_time) as LastFail by JoinKey, agent_id, causality_actor_process_image_name, actor_effective_username
| filter DistinctServices >= 3
| join type=inner (dataset = xdr_data | filter event_type in (ENUM.EVENT_LOG, ENUM.PROCESS) | filter causality_actor_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe") | filter actor_effective_username not in ("svc_redteam", "svc_pentest", "svc_vulnscan", "nessus", "qualys") | alter JoinKey = concat(agent_id, "_", causality_actor_process_id, "_", to_string(causality_actor_process_creation_time)) | alter CredTime = _time) as Creds JoinKey = Creds.JoinKey
| filter Creds.CredTime > LastFail and Creds.CredTime <= add(LastFail, 300000)
| join type=inner (dataset = xdr_data | filter event_type = ENUM.NETWORK | filter event_sub_type = ENUM.NETWORK_CONNECTION | filter causality_actor_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe") | filter is_known_private_ipv4(action_remote_ip) | filter action_remote_port in (445, 139, 22, 80, 443, 3389, 5985, 5986) | filter actor_effective_username not in ("svc_redteam", "svc_pentest", "svc_vulnscan", "nessus", "qualys") | alter JoinKey = concat(agent_id, "_", causality_actor_process_id, "_", to_string(causality_actor_process_creation_time)) | alter NewTargetIP = action_remote_ip, NewTargetTime = _time) as Pivot JoinKey = Pivot.JoinKey
| filter Pivot.NewTargetTime > Creds.CredTime and Pivot.NewTargetTime <= add(Creds.CredTime, 300000)
| filter not(array_contains(TargetsAttempted, Pivot.NewTargetIP))
| alter ChainDurationMinutes = divide(timestamp_diff(Pivot.NewTargetTime, FirstFail, "SECOND"), 60)
| filter ChainDurationMinutes <= 20
| dedup agent_id, causality_actor_process_image_name, Pivot.NewTargetIP by asc FirstFail
| fields agent_id, causality_actor_process_image_name, actor_effective_username, DistinctServices, Services, FirstFail, LastFail, Creds.CredTime as CredTime, Pivot.NewTargetIP as NewTargetIP, Pivot.NewTargetTime as NewTargetTime, ChainDurationMinutes
| sort asc ChainDurationMinutes