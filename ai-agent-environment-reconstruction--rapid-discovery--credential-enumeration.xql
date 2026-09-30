// Title: AI Agent Environment Reconstruction — Rapid System, Tool & Network Enumeration
// Author: detections.ai
// Severity: High
// MITRE ATLAS: AML.T0121
// MITRE ATT&CK: T1082, T1016, T1057, T1518

dataset = xdr_data
| filter event_type in (ENUM.PROCESS, ENUM.FILE)
| filter actor_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe")
| filter event_sub_type = ENUM.PROCESS_START or event_type = ENUM.FILE
| filter actor_effective_username != null and actor_effective_username not in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE")
| alter DiscoveryCategory = if(event_type = ENUM.PROCESS,
    if(action_process_command_line ~= "(?i)\\b(systeminfo|Get-ComputerInfo|hostname|uname\\s+-a|sw_vers|ver)\\b", "MachineOS",
        if(action_process_command_line ~= "(?i)\\b(ipconfig|Get-NetIPConfiguration|netsh\\s+interface|ifconfig|ip\\s+addr|route\\s+print)\\b", "NetworkEnv",
            if(action_process_command_line ~= "(?i)\\b(tasklist|Get-Process|ps\\s+aux|ps\\s+-ef)\\b", "ProcessDiscovery",
                if(action_process_command_line ~= "(?i)\\b(pip\\s+list|pip\\s+freeze|npm\\s+list|npm\\s+ls|Get-InstalledModule|Get-Package|code\\s+--list-extensions|conda\\s+list)\\b", "SoftwareTools", "")
            )
        )
    ),
    if(event_type = ENUM.FILE and (action_file_name in (".env", "credentials.json") or action_file_path ~= "(?i).*[\\\\/](\\.aws|\\.kube)[\\\\/].*"), "CredentialFiles", "")
)
| filter DiscoveryCategory != ""
| filter action_process_image_name not in ("MsMpEng.exe", "SenseIR.exe", "CcmExec.exe", "SCNotification.exe", "MonitoringHost.exe")
| alter Evidence = if(event_type = ENUM.PROCESS, action_process_command_line, concat(action_file_path, " (", event_sub_type, ")"))
| dedup agent_id, actor_process_image_name, DiscoveryCategory, Evidence by asc _time
| bin _time span = 10m
| comp count_distinct(DiscoveryCategory) as DistinctCategories, values(DiscoveryCategory) as Categories, count() as EventCount, values(Evidence) as SampleEvidence, min(_time) as FirstSeen, max(_time) as LastSeen by agent_id, agent_hostname, actor_primary_username, actor_process_image_name, _time
| filter DistinctCategories >= 5 and EventCount >= 6
| fields agent_id, agent_hostname, actor_primary_username, actor_process_image_name, DistinctCategories, Categories, EventCount, SampleEvidence, FirstSeen, LastSeen
| sort desc DistinctCategories, desc EventCount