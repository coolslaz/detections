// Title: AI Agent Security — Autonomous Host & Network Reconnaissance Burst
// MITRE ATT&CK: T1087, T1046, T1082, T1016
// Severity: High
// Author: detections.ai

config timeframe = 24h
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter actor_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe")
| filter actor_process_image_name not in ("nmap.exe", "nessus.exe", "qualys.exe", "rapid7.exe", "tenable.exe", "nexpose.exe", "openvas.exe", "lansweeper.exe", "pdq.exe")
| alter DiscoveryCategory = if(action_process_command_line ~= "(?i)\\b(whoami|net (user|group|localgroup)|Get-AD(User|Computer|Group)|nltest|dsquery)\\b", "AccountDiscovery",
    if(action_process_command_line ~= "(?i)\\b(netstat|arp -a|nmap|Test-NetConnection|portqry|Get-NetTCPConnection)\\b", "NetworkServiceDiscovery",
    if(action_process_command_line ~= "(?i)\\b(systeminfo|Get-ComputerInfo|hostname|uname -a|wmic os)\\b", "SystemInformationDiscovery",
    if(action_process_command_line ~= "(?i)\\b(ipconfig|Get-NetIPConfiguration|route print|netsh interface|ifconfig|ip addr|nslookup)\\b", "NetworkConfigDiscovery", ""))))
| filter DiscoveryCategory != ""
| bin _time span = 10m
| comp count_distinct(DiscoveryCategory) as DistinctCategories, values(DiscoveryCategory) as Categories, count() as CommandCount, list(action_process_command_line) as SampleCommands, earliest(_time) as FirstSeen, latest(_time) as LastSeen by agent_id, agent_hostname, actor_primary_username, actor_process_image_name, actor_process_pid, _time
| filter DistinctCategories >= 4 and CommandCount >= 6
| dedup agent_hostname, actor_process_pid, FirstSeen by asc FirstSeen
| fields agent_id, agent_hostname, actor_primary_username, actor_process_image_name, DistinctCategories, Categories, CommandCount, SampleCommands, FirstSeen, LastSeen
| sort desc DistinctCategories, desc CommandCount