/* Title: MCP Tool Poisoning — Configuration Change Followed by Unexpected Tool Execution */
/* MITRE ATT&CK: T1195.002, T1565.001, T1059 */
/* Severity: High */
/* Author: detections.ai */
dataset = xdr_data
| filter event_type = ENUM.FILE
  and (action_file_name in ("mcp.json", "claude_desktop_config.json")
       or action_file_path ~= ".*[\\/]\.cursor[\\/].*"
       or action_file_path ~= ".*[\\/]\.claude[\\/].*"
       or action_file_path ~= ".*[\\/]mcp[\\/].*")
| alter ConfigModTime = _time, ConfigModPath = action_file_path, ConfigModSha256 = action_file_sha256, ConfigModProc = actor_process_image_name
| join type=inner (
    dataset = xdr_data
    | filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
    | filter action_process_image_name in ("node.exe", "node", "npx.exe", "npx", "python.exe", "python3", "python")
    | filter not (
        actor_process_image_name in ("Cursor.exe", "cursor", "Claude.exe", "claude-desktop", "claude")
        and action_process_command_line ~= ".*(--list-tools|--list-servers|mcp\\s+list|--describe|--capabilities).*"
      )
    | alter LaunchTime = _time, ToolCommandLine = action_process_command_line, ToolProcessId = action_process_image_pid
  ) as ToolProcess ToolProcess.agent_hostname = agent_hostname
| filter ConfigModTime <= ToolProcess.LaunchTime and timestamp_diff(ToolProcess.LaunchTime, ConfigModTime, "MINUTE") <= 10
| dedup agent_hostname, ToolProcess.ToolProcessId by desc ConfigModTime
| join type=inner (
    dataset = xdr_data
    | filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
    | filter action_process_image_name in ("powershell.exe", "pwsh.exe", "bash", "sh", "cmd.exe")
    | alter ScriptTime = _time, ScriptCommandLine = action_process_command_line, ScriptProcessId = action_process_image_pid, ScriptParentId = actor_process_image_pid
  ) as ScriptChild ScriptChild.agent_hostname = agent_hostname
| filter ScriptChild.ScriptParentId = ToolProcess.ToolProcessId
  and ScriptChild.ScriptTime >= ToolProcess.LaunchTime
  and timestamp_diff(ScriptChild.ScriptTime, ToolProcess.LaunchTime, "MINUTE") <= 5
| join type=inner (
    dataset = xdr_data
    | filter event_type = ENUM.NETWORK
    | alter ConnTime = _time, ConnInitiatingProcessId = actor_process_image_pid, RemoteUrl = dns_query_name
  ) as ExternalConn ExternalConn.agent_hostname = agent_hostname
| filter ExternalConn.ConnInitiatingProcessId = ScriptChild.ScriptProcessId
  and ExternalConn.ConnTime >= ScriptChild.ScriptTime
  and timestamp_diff(ExternalConn.ConnTime, ScriptChild.ScriptTime, "MINUTE") <= 10
  and ExternalConn.RemoteUrl != null
  and not (ExternalConn.RemoteUrl in ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com"))
| alter ChainDurationMinutes = timestamp_diff(ExternalConn.ConnTime, ConfigModTime, "MINUTE")
| fields agent_hostname, actor_primary_username, ConfigModTime, ConfigModPath, ConfigModSha256, LaunchTime, ToolCommandLine, ScriptTime, ScriptCommandLine, ConnTime, RemoteUrl, ChainDurationMinutes
| dedup agent_hostname, ConfigModSha256, ScriptCommandLine, RemoteUrl by desc ConnTime
| sort desc ConnTime