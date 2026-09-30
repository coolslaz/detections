/* Title: Multimodal Prompt Injection — Image/PDF Input Followed by AI Agent Tool Execution
 * MITRE ATLAS: AML.T0129, AML.T0051.001
 * MITRE ATT&CK: T1204, T1059, T1105
 * Author: Arnold Chan */
dataset = xdr_data
| filter event_type = ENUM.FILE and event_sub_type = ENUM.FILE_CREATE_NEW
| filter action_file_name ~= "(?i)^.+\.(pdf|png|jpg|jpeg|gif|bmp|mp3|wav|mp4)$"
| filter actor_process_image_name in ("msedge.exe", "chrome.exe", "firefox.exe", "outlook.exe", "olk.exe", "teams.exe")
| filter actor_process_image_path ~= "(?i)^C:\\Program Files( \(x86\))?\\.*"
| filter action_file_path ~= "(?i).*(\\Downloads\\|\\Attachments\\|\\INetCache\\|\\Temporary Internet Files\\|\\Outlook\\).*"
| alter IngestTime = _time, IngestedFileName = action_file_name
| join type=inner (dataset = xdr_data | filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START | filter action_process_image_name in ("claude.exe", "cursor.exe", "chatgpt.exe", "githubcopilot.exe", "copilot.exe") | filter action_process_image_path ~= "(?i)^C:\\(Program Files( \(x86\))?|Users\\[^\]+\\AppData\\Local\\Programs)\\.*" | alter AgentProcessId = action_process_pid, AgentFileName = action_process_image_name, AccessTime = _time) as agent_access agent_id = agent_access.agent_id
| filter agent_access.AccessTime > IngestTime and timestamp_diff(agent_access.AccessTime, IngestTime, "MINUTE") <= 10
| filter agent_access.action_process_command_line contains IngestedFileName
| comp min(AccessTime) as AccessTime by agent_id, IngestTime, IngestedFileName, AgentProcessId, AgentFileName
| join type=inner (dataset = xdr_data | filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START | filter action_process_image_name in ("powershell.exe", "pwsh.exe", "cmd.exe", "bash", "sh") | alter ExecTime = _time, ExecCommandLine = action_process_command_line, ExecImagePath = action_process_image_path, TriggerType = "ShellExecution") as shell_exec agent_id = shell_exec.agent_id
| filter shell_exec.ExecTime > AccessTime and timestamp_diff(shell_exec.ExecTime, AccessTime, "MINUTE") <= 5
| filter shell_exec.ExecImagePath ~= "(?i)^C:\\Windows\\System32\\.*" or shell_exec.ExecImagePath ~= "(?i)^C:\\Program Files.*"
| filter shell_exec.ExecCommandLine ~= "(?i).*(\s-enc\s|\s-EncodedCommand\s|FromBase64String|DownloadString|DownloadFile|IEX\s|Invoke-Expression|Invoke-WebRequest|\biwr\b|\bcurl\b|\bwget\b|certutil|Net\.WebClient|-WindowStyle\s+Hidden|-w\s+hidden).*" or shell_exec.ExecCommandLine contains IngestedFileName
| dedup agent_id, IngestedFileName, AgentProcessId, shell_exec.ExecCommandLine by asc shell_exec.ExecTime
| fields agent_id, IngestTime, IngestedFileName, AccessTime, AgentProcessId, AgentFileName, TriggerType, shell_exec.ExecImagePath, shell_exec.ExecCommandLine, shell_exec.ExecTime as FinalStageTime
| sort desc FinalStageTime