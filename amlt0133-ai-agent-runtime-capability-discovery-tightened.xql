// AI Agent Security — Runtime Tool & Permission Enumeration
// MITRE ATLAS: AML.T0133 (Discover AI Agent Runtime Capabilities)
// MITRE ATT&CK: T1082, T1518, T1083, T1016
// Author: Arnold Chan
// Severity: Medium
// Timeframe: 10m window

dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter actor_process_image_name in ("claude.exe", "cursor.exe", "aider.exe", "autogpt.exe", "langchain.exe")
    or actor_process_command_line ~= "(?i)\\b(claude|cursor|aider|autogpt|langchain)\\b"
| filter actor_process_image_name not in ("CursorUpdater.exe", "claude_desktop_updater.exe", "Squirrel.exe", "update.exe", "AutoUpdater.exe")
| filter not (action_process_command_line ~= "(?i)(--version|--help|-v\\b|healthcheck|self-?test|self-?diagnos|update\\.exe|installer)")
| alter DiscoveryCategory = if(
    action_process_command_line ~= "(?i)(ipconfig|Get-NetIPConfiguration|netsh\\s+interface|ifconfig|ip\\s+addr)", "Network",
    if(action_file_path ~= "(?i).*(mcp\\.json|claude_desktop_config\\.json|settings\\.json|\\.cursor|\\.claude|\\.vscode).*"
        or (action_process_command_line ~= "(?i)(Get-ChildItem|^dir\\b|^ls\\b|^find\\b|^tree\\b)"
            and action_process_command_line ~= "(?i)(plugins|connectors|extensions|tools|mcp)"), "FileDiscovery",
    if(action_process_command_line ~= "(?i)(pip\\s+(list|freeze)|npm\\s+(list|ls)|code\\s+--list-extensions|Get-InstalledModule|Get-Package|conda\\s+list|gem\\s+list)", "SoftwareDiscovery",
    if(action_process_command_line ~= "(?i)(systeminfo|Get-ComputerInfo|uname\\s+-a|sw_vers|hostnamectl|printenv|Get-ChildItem\\s+env:)", "SystemDiscovery", "Other"))))
| filter DiscoveryCategory != "Other"
| bin _time span = 10m
| comp count_distinct(DiscoveryCategory) as DistinctCategories by agent_hostname, actor_process_image_name, _time
| filter DistinctCategories >= 3
| dedup agent_hostname, actor_process_image_name, _time by asc _time