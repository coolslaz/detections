// AI Agent Security — Autonomous Recon -> Credential Access -> Collection -> Exfiltration
// Severity: High
// ATT&CK: T1046, T1552.001, T1078, T1005, T1567
// ATLAS: AML.T0124
// Author: detections.ai

dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name in ("claude", "cursor", "copilot", "aider", "autogpt", "auto-gpt", "langchain", "agentgpt", "gpt-engineer") or action_process_command_line ~= "(?i)(claude|cursor-agent|copilot|aider|auto-?gpt|langchain|agentgpt|gpt-engineer|agent\\.py)")
| filter actor_primary_username not in ("svc_ci", "svc_ansible", "svc_jenkins", "svc_orchestrator", "system") and action_process_image_path not contains "\\ci\\" and action_process_image_path not contains "/opt/ci/"
| comp min(_time) as AgentStart by agent_id, actor_primary_username, agent_hostname
| join type=inner (
    dataset = xdr_data
    | filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
    | filter action_process_image_name in ("nmap.exe", "nmap", "arp.exe", "ipconfig.exe", "nltest.exe", "nslookup.exe", "portqry.exe", "masscan.exe", "powershell.exe", "pwsh.exe")
    | filter action_process_command_line ~= "(?i)(net\\s+view|net\\s+group|Get-NetTCPConnection|Test-NetConnection|nmap|masscan|portqry)"
    | comp count_distinct(action_process_command_line) as DiscoveryCount, min(_time) as FirstDiscovery, max(_time) as LastDiscovery by agent_id
    | filter DiscoveryCount >= 4
) as Disc Disc.agent_id = agent_id
| join type=inner (
    dataset = xdr_data
    | filter event_type = ENUM.FILE
    | filter action_file_name in (".env", "id_rsa", "credentials.json", ".npmrc", ".git-credentials", "unattend.xml", "web.config", ".kdbx", "secrets.yaml") or action_file_path ~= "(?i).*\\.aws[\\\\/]credentials$" or action_file_path ~= "(?i).*\\.kube[\\\\/]config$"
    | comp count() as CredHits, min(_time) as CredAccessTime by agent_id
    | filter CredHits >= 1
) as Creds Creds.agent_id = agent_id
| join type=inner (
    dataset = xdr_data
    | filter event_type = ENUM.FILE
    | filter action_file_name ~= "(?i).*\\.(zip|7z|rar|tar\\.gz)$" and (action_file_path ~= "(?i).*[\\\\/](staging|temp|tmp)[\\\\/].*")
    | comp count() as CollectionHits, min(_time) as CollectionTime by agent_id
    | filter CollectionHits >= 1
) as Coll Coll.agent_id = agent_id
| join type=inner (
    dataset = xdr_data
    | filter event_type = ENUM.NETWORK
    | filter dns_query_name ~= "(?i)(transfer\\.sh|pastebin\\.com|anonfiles\\.com|mega\\.nz|dropbox\\.com|drive\\.google\\.com|wetransfer\\.com|0x0\\.st|file\\.io|cdn\\.discordapp\\.com|t\\.me)$"
    | comp count() as ExfilHits, min(_time) as ExfilTime, values(dns_query_name) as RemoteDomain by agent_id
    | filter ExfilHits >= 1
) as Exfil Exfil.agent_id = agent_id
| filter AgentStart <= Disc.FirstDiscovery and Disc.FirstDiscovery <= Creds.CredAccessTime and Creds.CredAccessTime <= Coll.CollectionTime and Coll.CollectionTime <= Exfil.ExfilTime
| alter ChainDurationMinutes = divide(timestamp_diff(Exfil.ExfilTime, AgentStart, "SECOND"), 60)
| filter timestamp_diff(Exfil.ExfilTime, AgentStart, "MINUTE") <= 15
| fields agent_id, agent_hostname, actor_primary_username, AgentStart, Disc.FirstDiscovery, Disc.DiscoveryCount, Creds.CredAccessTime, Coll.CollectionTime, Exfil.ExfilTime, Exfil.RemoteDomain, ChainDurationMinutes
| dedup agent_id by asc Exfil.ExfilTime
| sort desc Exfil.ExfilTime